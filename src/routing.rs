//! Restart-stable forwarding identity and stateless dialog-route credentials.
//!
//! A Record-Route token lets the original endpoints keep using a dialog after
//! their registrations expire. It grants the same routing permission as a
//! registered source, but only for that source address and Call-ID, and it
//! names both endpoints: without a live registration, requests are only
//! relayed to the token's other endpoint. No dialog table or idle cleanup
//! timer is needed. Digest nonces use a separate, per-process secret and
//! still become stale after restart.

use crate::util::{random_hex, WARN};
use md5::{Digest, Md5};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

fn key_path(state: &Path) -> PathBuf {
    let mut path = state.as_os_str().to_os_string();
    path.push(".key");
    PathBuf::from(path)
}

fn read_key(path: &Path) -> io::Result<String> {
    let key = std::fs::read_to_string(path)?;
    if key.len() != 32 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid routing key"));
    }
    Ok(key)
}

pub fn load_key(state: Option<&Path>) -> String {
    let fresh = random_hex();
    let Some(state) = state else { return fresh };
    let path = key_path(state);
    let result = (|| {
        match read_key(&path) {
            Ok(key) => return Ok(key),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        // Publish a complete key atomically, without replacing a key another
        // process might just have created. Keep it private even with a lax umask.
        let tmp = path.with_extension(format!("key-{}.tmp", random_hex()));
        let result = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(fresh.as_bytes())?;
            file.sync_all()?;
            match std::fs::hard_link(&tmp, &path) {
                Ok(()) => Ok(fresh.clone()),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => read_key(&path),
                Err(e) => Err(e),
            }
        })();
        let _ = std::fs::remove_file(tmp);
        result
    })();
    result.unwrap_or_else(|e: io::Error| {
        crate::log!(
            WARN,
            "cannot load/save routing key {}: {}; pending calls will not survive restart",
            path.display(),
            e
        );
        fresh
    })
}

fn mac(key: &str, data: &[u8]) -> String {
    // HMAC-MD5, reusing the existing digest dependency. Keys here are 32 bytes.
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for (i, b) in key.bytes().enumerate() {
        inner[i] ^= b;
        outer[i] ^= b;
    }
    let mut h = Md5::new();
    h.update(inner);
    h.update(data);
    let digest = h.finalize();
    let mut h = Md5::new();
    h.update(outer);
    h.update(digest);
    format!("{:x}", h.finalize())
}

fn endpoint_token(key: &str, call_id: &str, source: SocketAddr) -> String {
    mac(
        key,
        format!("dialog:{}:{}:{}", call_id.len(), call_id, source).as_bytes(),
    )
}

pub fn token(key: &str, call_id: &str, caller: SocketAddr, callee: SocketAddr) -> String {
    format!(
        "{}.{}",
        endpoint_token(key, call_id, caller),
        endpoint_token(key, call_id, callee)
    )
}

/// Constant-time string comparison.
pub fn equal(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |diff, (a, b)| diff | (a ^ b)) == 0
}

/// Was the token minted for a dialog of `source` (either endpoint)?
pub fn valid(key: &str, call_id: &str, source: SocketAddr, token: &str) -> bool {
    let Some((a, b)) = token.split_once('.') else {
        return false;
    };
    let want = endpoint_token(key, call_id, source);
    equal(a, &want) | equal(b, &want)
}

/// Was the token minted for a dialog between exactly these two endpoints (in
/// either direction)? Without a live registration, in-dialog requests are
/// only relayed between a dialog's original endpoints.
pub fn connects(key: &str, call_id: &str, from: SocketAddr, to: SocketAddr, token: &str) -> bool {
    let Some((a, b)) = token.split_once('.') else {
        return false;
    };
    let (f, t) = (
        endpoint_token(key, call_id, from),
        endpoint_token(key, call_id, to),
    );
    (equal(a, &f) & equal(b, &t)) | (equal(a, &t) & equal(b, &f))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_known_vector() {
        assert_eq!(
            mac("Jefe", b"what do ya want for nothing?"),
            "750c783e6ab0b503eaa86e310a5db738"
        );
    }

    #[test]
    fn route_tokens_are_bound_to_endpoints_and_call() {
        let key = random_hex();
        let a = "127.0.0.1:1000".parse().unwrap();
        let b = "[::1]:2000".parse().unwrap();
        let t = token(&key, "one", a, b);
        assert!(valid(&key, "one", a, &t));
        assert!(valid(&key, "one", b, &t));
        assert!(!valid(&key, "two", a, &t));
        assert!(!valid(&key, "one", "127.0.0.1:1001".parse().unwrap(), &t));
        assert!(!valid(&random_hex(), "one", a, &t));
        assert!(!valid(&key, "one", a, "invalid"));
    }

    #[test]
    fn route_tokens_connect_only_their_two_endpoints() {
        let key = random_hex();
        let a = "127.0.0.1:1000".parse().unwrap();
        let b = "[::1]:2000".parse().unwrap();
        let c = "127.0.0.1:3000".parse().unwrap();
        let t = token(&key, "one", a, b);
        assert!(connects(&key, "one", a, b, &t));
        assert!(connects(&key, "one", b, a, &t));
        assert!(!connects(&key, "one", a, c, &t));
        assert!(!connects(&key, "one", c, b, &t));
        assert!(!connects(&key, "one", a, a, &t));
        assert!(!connects(&key, "two", a, b, &t));
        assert!(!connects(&random_hex(), "one", a, b, &t));
        assert!(!connects(&key, "one", a, b, "invalid"));
        let same = token(&key, "one", a, a);
        assert!(connects(&key, "one", a, a, &same));
    }

    #[test]
    fn key_survives_restart_and_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::util::TestDir::create();
        let state = dir.join("bindings.txt");
        let key = load_key(Some(&state));
        assert_eq!(load_key(Some(&state)), key);
        assert_eq!(
            std::fs::metadata(key_path(&state)).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
