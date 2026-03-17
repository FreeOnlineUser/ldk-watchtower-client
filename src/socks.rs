//! Arti-based SOCKS5 proxy server.
//!
//! Runs a persistent SOCKS5 listener on 127.0.0.1:<port>.
//! All consumers (bitcoind, HTTP calls, watchtower) route through this.
//! One Arti instance, one set of circuits, one consensus cache.

use arti_client::{TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;
use tor_socksproto::{
    Buffer, Handshake as SocksHandshake, NextStep, SocksCmd, SocksProxyHandshake,
    SocksRequest, SocksStatus,
};

use log::{info, warn, error};
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

/// Global handle to the running proxy.
static PROXY: std::sync::Mutex<Option<ProxyHandle>> = std::sync::Mutex::new(None);

struct ProxyHandle {
    tor_client: Arc<TorClient<PreferredRuntime>>,
    stop_tx: watch::Sender<bool>,
    runtime: tokio::runtime::Runtime,
}

/// Start the Arti SOCKS5 proxy on 127.0.0.1:<port>.
///
/// Bootstraps Tor (or reuses cached consensus), then listens for SOCKS5
/// connections. Returns Ok on success.
pub fn start(state_dir: &str, cache_dir: &str, port: u16) -> Result<(), io::Error> {
    let mut proxy = PROXY.lock().unwrap();
    if proxy.is_some() {
        info!("SOCKS proxy already running");
        return Ok(());
    }

    info!("Starting Arti SOCKS proxy on 127.0.0.1:{}", port);

    // Multi-threaded runtime: listener + stream bridges run concurrently
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("runtime: {}", e)))?;

    // Bootstrap Arti
    let tor_client = rt.block_on(async {
        let mut builder = TorClientConfig::builder();
        builder.storage().state_dir(
            arti_client::config::CfgPath::new(state_dir.to_string())
        );
        builder.storage().cache_dir(
            arti_client::config::CfgPath::new(cache_dir.to_string())
        );
        builder.storage().permissions().dangerously_trust_everyone();

        let config = builder.build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("config: {}", e)))?;

        info!("Bootstrapping Arti...");
        let client = TorClient::create_bootstrapped(config).await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("bootstrap: {}", e)))?;
        info!("Arti bootstrapped successfully");

        Ok::<_, io::Error>(client)
    })?;

    let tor_client = Arc::new(tor_client);
    let (stop_tx, stop_rx) = watch::channel(false);

    // Spawn the listener loop
    let listener_client = Arc::clone(&tor_client);
    rt.spawn(async move {
        if let Err(e) = run_listener(listener_client, port, stop_rx).await {
            error!("SOCKS proxy listener error: {}", e);
        }
    });

    *proxy = Some(ProxyHandle {
        tor_client,
        stop_tx,
        runtime: rt,
    });
    info!("SOCKS proxy started on 127.0.0.1:{}", port);
    Ok(())
}

/// Stop the SOCKS proxy and tear down Arti.
pub fn stop() {
    let mut proxy = PROXY.lock().unwrap();
    if let Some(handle) = proxy.take() {
        info!("Stopping SOCKS proxy...");
        let _ = handle.stop_tx.send(true);
        // Runtime drops here, cancelling all tasks
        drop(handle);
        info!("SOCKS proxy stopped");
    }
}

/// Check if the proxy is running.
pub fn is_running() -> bool {
    PROXY.lock().unwrap().is_some()
}

/// Main listener loop: accept SOCKS5 connections and bridge them through Tor.
async fn run_listener(
    tor_client: Arc<TorClient<PreferredRuntime>>,
    port: u16,
    mut stop_rx: watch::Receiver<bool>,
) -> io::Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    info!("SOCKS proxy listening on 127.0.0.1:{}", port);

    loop {
        tokio::select! {
            biased;
            _ = stop_rx.changed() => {
                info!("SOCKS proxy received stop signal");
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, addr)) => {
                        let client = Arc::clone(&tor_client);
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(client, stream).await {
                                // Don't log broken pipe / connection reset — normal
                                if e.kind() != io::ErrorKind::BrokenPipe
                                    && e.kind() != io::ErrorKind::ConnectionReset
                                {
                                    warn!("SOCKS connection from {} error: {}", addr, e);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        warn!("Accept error: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Handle a single SOCKS5 connection.
///
/// 1. Parse SOCKS5 handshake (using tor-socksproto)
/// 2. Connect to target through Tor
/// 3. Bridge the two streams
async fn handle_connection(
    tor_client: Arc<TorClient<PreferredRuntime>>,
    mut client: tokio::net::TcpStream,
) -> io::Result<()> {
    // Parse SOCKS5 handshake
    let request = perform_handshake(&mut client).await?;

    let target = match request.command() {
        SocksCmd::CONNECT => {
            format!("{}:{}", request.addr(), request.port())
        }
        other => {
            if let Ok(reply) = request.reply(SocksStatus::COMMAND_NOT_SUPPORTED, None) {
                let _ = client.write_all(&reply).await;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported SOCKS command: {:?}", other),
            ));
        }
    };

    info!("SOCKS CONNECT to {}", target);

    // Connect through Tor
    let tor_stream = match tor_client.connect(&*target).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("Tor connect to {} failed: {}", target, e);
            if let Ok(reply) = request.reply(SocksStatus::GENERAL_FAILURE, None) {
                let _ = client.write_all(&reply).await;
            }
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("Tor connect failed: {}", e),
            ));
        }
    };

    // Send success reply
    let reply = request.reply(SocksStatus::SUCCEEDED, None)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("reply encode: {}", e)))?;
    client.write_all(&reply).await?;

    // Bridge streams: client <-> tor
    // Arti DataStream implements futures::AsyncRead/Write.
    // Wrap with tokio compat layer.
    let tor_stream = tokio_util::compat::FuturesAsyncReadCompatExt::compat(tor_stream);
    let (mut tor_read, mut tor_write) = tokio::io::split(tor_stream);
    let (mut client_read, mut client_write) = tokio::io::split(client);

    // Bidirectional copy until either side closes
    let c2t = tokio::io::copy(&mut client_read, &mut tor_write);
    let t2c = tokio::io::copy(&mut tor_read, &mut client_write);

    tokio::select! {
        r = c2t => { if let Err(e) = r { return Err(e); } }
        r = t2c => { if let Err(e) = r { return Err(e); } }
    }

    Ok(())
}

/// Perform the SOCKS5 handshake with a client.
///
/// Uses tor-socksproto's step-based API:
/// - NextStep::Send → write to client
/// - NextStep::Recv → read from client
/// - NextStep::Finished → handshake complete, return SocksRequest
async fn perform_handshake(
    client: &mut tokio::net::TcpStream,
) -> io::Result<SocksRequest> {
    let mut handshake = SocksProxyHandshake::new();
    let mut buf = Buffer::new();

    loop {
        match handshake.step(&mut buf) {
            Ok(NextStep::Send(data)) => {
                client.write_all(&data).await?;
            }
            Ok(NextStep::Recv(mut recv)) => {
                let dest = recv.buf();
                let n = client.read(dest).await?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "client disconnected during SOCKS handshake",
                    ));
                }
                recv.note_received(n)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            }
            Ok(NextStep::Finished(finished)) => {
                let (request, _readahead) = finished.into_output_and_vec();
                return Ok(request);
            }
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("SOCKS handshake error: {}", e),
                ));
            }
        }
    }
}
