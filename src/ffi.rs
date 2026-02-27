//! JNI-compatible FFI for Android.
//!
//! Provides a synchronous, C-ABI interface that Kotlin calls via JNA.
//! Each function takes/returns simple types (pointers, byte arrays, ints).

use crate::blob::{self, JusticeKitV0};
use crate::client::{PendingBackup, TowerConfig, WatchtowerClient};
use crate::wire::BlobType;
use std::ffi::c_char;
use std::sync::Mutex;
use tokio::runtime::{Builder as RtBuilder, Runtime};

/// Opaque handle to a watchtower client + tokio runtime.
struct ClientHandle {
    client: WatchtowerClient,
    rt: Runtime,
}

static HANDLE: Mutex<Option<ClientHandle>> = Mutex::new(None);

/// Initialize a watchtower client and connect to the tower.
///
/// # Parameters
/// - `address`: Tower address as "host:port" (null-terminated C string)
/// - `tower_pubkey`: 33-byte compressed secp256k1 public key
/// - `client_key`: 32-byte private key
/// - `max_updates`: Max updates per session
/// - `sweep_fee_rate`: Fee rate in sat/kweight
///
/// # Returns
/// 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn wtclient_connect(
    address: *const c_char,
    tower_pubkey: *const u8,
    client_key: *const u8,
    max_updates: u16,
    sweep_fee_rate: u64,
) -> i32 {
    let address = unsafe {
        if address.is_null() { return -1; }
        match std::ffi::CStr::from_ptr(address).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        }
    };

    let tower_pubkey: [u8; 33] = unsafe {
        if tower_pubkey.is_null() { return -1; }
        let mut buf = [0u8; 33];
        std::ptr::copy_nonoverlapping(tower_pubkey, buf.as_mut_ptr(), 33);
        buf
    };

    let client_key: [u8; 32] = unsafe {
        if client_key.is_null() { return -1; }
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(client_key, buf.as_mut_ptr(), 32);
        buf
    };

    let config = TowerConfig {
        address,
        tower_pubkey,
        client_key,
        blob_type: BlobType::ALTRUIST_ANCHOR_COMMIT,
        max_updates,
        sweep_fee_rate,
    };

    let rt: Runtime = match RtBuilder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(_) => return -1,
    };

    let mut client = WatchtowerClient::new(config);
    let result = rt.block_on(client.connect());

    match result {
        Ok(()) => {
            let mut handle = HANDLE.lock().unwrap();
            *handle = Some(ClientHandle { client, rt });
            0
        }
        Err(e) => {
            log::error!("wtclient_connect failed: {}", e);
            -1
        }
    }
}

/// Send a single backup to the tower.
///
/// # Parameters
/// - `breach_txid`: 32-byte breach transaction ID
/// - `rev_pubkey`: 33-byte revocation pubkey
/// - `local_delay_pubkey`: 33-byte local delay pubkey
/// - `csv_delay`: CSV delay value
/// - `sweep_addr`: sweep address bytes
/// - `sweep_addr_len`: length of sweep address
/// - `to_local_sig`: 64-byte to_local signature
/// - `to_remote_pubkey`: 33-byte to_remote pubkey
/// - `to_remote_sig`: 64-byte to_remote signature
///
/// # Returns
/// 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn wtclient_send_backup(
    breach_txid: *const u8,
    rev_pubkey: *const u8,
    local_delay_pubkey: *const u8,
    csv_delay: u32,
    sweep_addr: *const u8,
    sweep_addr_len: u32,
    to_local_sig: *const u8,
    to_remote_pubkey: *const u8,
    to_remote_sig: *const u8,
) -> i32 {
    // Safety: all pointers must be valid
    if breach_txid.is_null() || rev_pubkey.is_null() || local_delay_pubkey.is_null()
        || sweep_addr.is_null() || to_local_sig.is_null()
        || to_remote_pubkey.is_null() || to_remote_sig.is_null()
    {
        return -1;
    }

    let breach_txid: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(breach_txid, buf.as_mut_ptr(), 32);
        buf
    };

    let justice_kit = unsafe {
        let mut rev = [0u8; 33];
        std::ptr::copy_nonoverlapping(rev_pubkey, rev.as_mut_ptr(), 33);

        let mut ldp = [0u8; 33];
        std::ptr::copy_nonoverlapping(local_delay_pubkey, ldp.as_mut_ptr(), 33);

        let sweep_len = sweep_addr_len as usize;
        let mut sweep = vec![0u8; sweep_len];
        std::ptr::copy_nonoverlapping(sweep_addr, sweep.as_mut_ptr(), sweep_len);

        let mut tls = [0u8; 64];
        std::ptr::copy_nonoverlapping(to_local_sig, tls.as_mut_ptr(), 64);

        let mut trp = [0u8; 33];
        std::ptr::copy_nonoverlapping(to_remote_pubkey, trp.as_mut_ptr(), 33);

        let mut trs = [0u8; 64];
        std::ptr::copy_nonoverlapping(to_remote_sig, trs.as_mut_ptr(), 64);

        JusticeKitV0 {
            revocation_pubkey: rev,
            local_delay_pubkey: ldp,
            csv_delay,
            sweep_address: sweep,
            to_local_sig: tls,
            to_remote_pubkey: trp,
            to_remote_sig: trs,
        }
    };

    let backup = PendingBackup {
        breach_txid,
        justice_kit,
    };

    let mut handle = HANDLE.lock().unwrap();
    let h = match handle.as_mut() {
        Some(h) => h,
        None => return -1,
    };

    match h.rt.block_on(h.client.send_backup(&backup)) {
        Ok(()) => 0,
        Err(e) => {
            log::error!("wtclient_send_backup failed: {}", e);
            -1
        }
    }
}

/// Disconnect from the tower and clean up.
#[no_mangle]
pub extern "C" fn wtclient_disconnect() {
    let mut handle = HANDLE.lock().unwrap();
    *handle = None;
}

/// Check if client is connected.
///
/// Returns 1 if connected, 0 if not.
#[no_mangle]
pub extern "C" fn wtclient_is_connected() -> i32 {
    let handle = HANDLE.lock().unwrap();
    match handle.as_ref() {
        Some(h) if h.client.is_connected() => 1,
        _ => 0,
    }
}

/// Get remaining update slots.
///
/// Returns remaining count, or -1 if not connected.
#[no_mangle]
pub extern "C" fn wtclient_remaining_updates() -> i32 {
    let handle = HANDLE.lock().unwrap();
    match handle.as_ref() {
        Some(h) => match h.client.remaining_updates() {
            Some(n) => n as i32,
            None => -1,
        },
        None => -1,
    }
}
