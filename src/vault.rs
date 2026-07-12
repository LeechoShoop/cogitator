//! Shared passphrase-based encryption-at-rest for Cogitator's on-disk
//! artifacts (workspaces, session vaults, and anything added later).
//!
//! Wraps an arbitrary `Serialize`/`DeserializeOwned` payload in an
//! AES-256-GCM envelope, keyed by a passphrase run through Argon2id. This
//! module only knows about bytes and serde — it has no idea what a
//! `WorkspaceData` or a `SessionProfile` is. Callers serialise their own
//! domain type via `encrypt_to_file`/`decrypt_from_file`; all the crypto
//! (salt/nonce generation, key derivation, AEAD encrypt/decrypt) lives here
//! exactly once so callers never touch `aes_gcm`/`argon2` directly.
//!
//! # On-disk format
//!
//! A small outer JSON envelope (`Envelope`) whose fields are themselves
//! base64 — salt and nonce in the clear (both are safe to expose; only the
//! derived key matters), ciphertext opaque. This keeps the file valid,
//! inspectable JSON even though its contents are unreadable without the
//! passphrase.
//!
//! # Quick-start
//!
//! ```rust,ignore
//! vault::encrypt_to_file(&my_data, "thing.vault", &passphrase)?;
//! let my_data: MyType = vault::decrypt_from_file("thing.vault", &passphrase)?;
//! ```

use std::io;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

// ─── Error type ───────────────────────────────────────────────────────────────

/// All errors that can arise inside this module. The public
/// `encrypt_to_file`/`decrypt_from_file` functions convert this into
/// `io::Error` at the module boundary via the `From` implementation below,
/// so callers never need to name this type.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// Argon2id key-derivation failed (internal error string from the crate).
    #[error("Argon2id key derivation failed: {0}")]
    KeyDerivation(String),

    /// AES-256-GCM key construction rejected the derived bytes (should never
    /// happen in practice since we always produce exactly 32 bytes).
    #[error("bad AES-256 key length: {0}")]
    BadKeyLength(String),

    /// AES-GCM authenticated encryption failed.
    #[error("AES-GCM encryption failed: {0}")]
    Encryption(String),

    /// AES-GCM authentication-tag check failed. AES-GCM cannot distinguish a
    /// wrong passphrase from a tampered/corrupted file — the remedy is the
    /// same either way.
    #[error("decryption failed \u2014 wrong passphrase or corrupted file")]
    WrongPassphraseOrCorrupted,

    /// The file's `format` field doesn't match `FORMAT_MARKER`.
    #[error("not a Cogitator vault file (format marker was '{found}')")]
    UnknownFormat { found: String },

    /// The stored nonce has a length we don't expect.
    #[error("corrupt vault file: unexpected nonce length")]
    MalformedEnvelope,

    /// JSON serialisation / deserialisation error (wraps `serde_json::Error`).
    #[error("serialisation error: {0}")]
    Serialise(#[from] serde_json::Error),

    /// Underlying filesystem I/O error (pass-through).
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl From<VaultError> for io::Error {
    fn from(e: VaultError) -> Self {
        match e {
            // Unwrap the inner io::Error rather than double-wrapping.
            VaultError::Io(inner) => inner,
            // Everything else maps to InvalidData, preserving the typed
            // Display message as the error description.
            other => io::Error::new(io::ErrorKind::InvalidData, other),
        }
    }
}

/// Marker written into every envelope's `format` field. `decrypt_from_file`
/// rejects anything else; `is_encrypted_file` uses it to distinguish a vault
/// envelope from a legacy plaintext file (or anything else at that path)
/// without attempting a decrypt. Bump if the envelope schema below ever
/// changes incompatibly.
pub const FORMAT_MARKER: &str = "cogitator-vault-v1";

/// Argon2id salt length in bytes. 16 bytes is the RFC 9106-recommended
/// minimum for password hashing.
const SALT_LEN: usize = 16;

/// AES-256-GCM key length in bytes.
const KEY_LEN: usize = 32;

/// AES-GCM nonce length in bytes (96-bit, as mandated by the GCM spec).
const NONCE_LEN: usize = 12;

/// On-disk envelope. Every field is base64-encoded text so the file stays
/// valid, inspectable JSON even though its contents are opaque.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Envelope {
    /// Always `FORMAT_MARKER` — lets callers fail fast on anything that
    /// isn't a Cogitator vault file.
    format: String,
    /// Argon2id salt (random per save), base64.
    salt_b64: String,
    /// AES-GCM nonce (random per save), base64.
    nonce_b64: String,
    /// AES-256-GCM ciphertext of the caller's serialised payload, including
    /// the 16-byte authentication tag appended by the `aead` crate.
    ciphertext_b64: String,
}

/// Derive a 32-byte AES-256 key from `passphrase` and `salt` using Argon2id
/// with the crate's default (RFC-9106-recommended) cost parameters.
///
/// Deliberately not tunable from the CLI: every vault file uses the same KDF
/// cost, so a file saved on one machine decrypts the same way on another
/// without needing to persist the parameters alongside it.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], VaultError> {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

/// Serialise `data` to JSON, encrypt it with a key derived from `passphrase`
/// (Argon2id, random salt) via AES-256-GCM (random nonce), and write the
/// resulting envelope to `path`.
///
/// A fresh salt and nonce are generated on every call, so encrypting the
/// same `data` twice with the same passphrase produces two different
/// ciphertexts.
pub fn encrypt_to_file<T, P>(data: &T, path: P, passphrase: &str) -> io::Result<()>
where
    T: Serialize,
    P: AsRef<Path>,
{
    encrypt_to_file_inner(data, path, passphrase).map_err(io::Error::from)
}

fn encrypt_to_file_inner<T, P>(data: &T, path: P, passphrase: &str) -> Result<(), VaultError>
where
    T: Serialize,
    P: AsRef<Path>,
{
    let plaintext = serde_json::to_vec(data)?;

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key_bytes = derive_key(passphrase, &salt)?;

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| VaultError::BadKeyLength(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| VaultError::Encryption(e.to_string()))?;

    let envelope = Envelope {
        format: FORMAT_MARKER.to_string(),
        salt_b64: base64_encode(&salt),
        nonce_b64: base64_encode(&nonce_bytes),
        ciphertext_b64: base64_encode(&ciphertext),
    };

    let json = serde_json::to_string_pretty(&envelope)?;
    std::fs::write(path, json).map_err(VaultError::Io)
}

/// Read an envelope from `path`, derive the key from `passphrase` + the
/// stored salt, and decrypt + deserialise back into `T`.
///
/// Returns an `io::ErrorKind::InvalidData` error both for a wrong passphrase
/// and for a corrupted/tampered file — AES-GCM's authentication tag check
/// can't distinguish the two, and for the caller the remedy ("check the
/// passphrase, or find a good backup") is the same either way.
pub fn decrypt_from_file<T, P>(path: P, passphrase: &str) -> io::Result<T>
where
    T: DeserializeOwned,
    P: AsRef<Path>,
{
    decrypt_from_file_inner(path, passphrase).map_err(io::Error::from)
}

fn decrypt_from_file_inner<T, P>(path: P, passphrase: &str) -> Result<T, VaultError>
where
    T: DeserializeOwned,
    P: AsRef<Path>,
{
    let contents = std::fs::read_to_string(path)?;
    let envelope: Envelope = serde_json::from_str(&contents)?;

    if envelope.format != FORMAT_MARKER {
        return Err(VaultError::UnknownFormat { found: envelope.format });
    }

    let salt = base64_decode(&envelope.salt_b64);
    let nonce_bytes = base64_decode(&envelope.nonce_b64);
    let ciphertext = base64_decode(&envelope.ciphertext_b64);

    if nonce_bytes.len() != NONCE_LEN {
        return Err(VaultError::MalformedEnvelope);
    }

    let key_bytes = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| VaultError::BadKeyLength(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| VaultError::WrongPassphraseOrCorrupted)?;

    Ok(serde_json::from_slice(&plaintext)?)
}

/// `true` if `path` looks like a vault envelope rather than a legacy
/// plaintext file (or anything else). Lets callers decide whether to prompt
/// for a passphrase at all, so pre-existing plaintext files keep loading
/// with no prompt until they're re-saved through the encrypted path.
pub fn is_encrypted_file<P: AsRef<Path>>(path: P) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<Envelope>(&s).ok())
        .map(|e| e.format == FORMAT_MARKER)
        .unwrap_or(false)
}

// ─── Base-64 helpers (no external crate needed — stdlib only) ─────────────────
//
// Small and self-contained on purpose: this module shouldn't need to reach
// into workspace.rs (or vice versa) just to encode a salt.

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };

        out.push(ALPHABET[(b0 >> 2)] as char);
        out.push(ALPHABET[((b0 & 0x3) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((b1 & 0xf) << 2) | (b2 >> 6)] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(s: &str) -> Vec<u8> {
    let decode_char = |c: char| -> Option<u8> {
        match c {
            'A'..='Z' => Some(c as u8 - b'A'),
            'a'..='z' => Some(c as u8 - b'a' + 26),
            '0'..='9' => Some(c as u8 - b'0' + 52),
            '+' => Some(62),
            '/' => Some(63),
            _ => None,
        }
    };

    let bytes: Vec<u8> = s.chars().filter_map(decode_char).collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        out.push((chunk[0] << 2) | (chunk[1] >> 4));
        if chunk.len() > 2 {
            out.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        if chunk.len() > 3 {
            out.push((chunk[2] << 6) | chunk[3]);
        }
    }
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Payload {
        secret: String,
        numbers: Vec<u32>,
    }

    fn sample() -> Payload {
        Payload { secret: "hunter2topsecret".to_string(), numbers: vec![1, 2, 3] }
    }

    fn tmp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("cogitator_vault_test_{}_{}.vault", tag, std::process::id()))
    }

    #[test]
    fn base64_roundtrip() {
        let data: Vec<u8> = (0u8..=255).collect();
        assert_eq!(base64_decode(&base64_encode(&data)), data);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let path = tmp_path("roundtrip");
        let payload = sample();

        encrypt_to_file(&payload, &path, "correct horse battery staple").unwrap();
        let loaded: Payload = decrypt_from_file(&path, "correct horse battery staple").unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(loaded, payload);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let path = tmp_path("wrongpass");
        encrypt_to_file(&sample(), &path, "the right one").unwrap();

        let result: io::Result<Payload> = decrypt_from_file(&path, "definitely not it");
        let _ = std::fs::remove_file(&path);

        let err = result.expect_err("wrong passphrase must fail to decrypt");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn ciphertext_does_not_leak_plaintext_secret() {
        let path = tmp_path("leak");
        let payload = sample();
        encrypt_to_file(&payload, &path, "some passphrase").unwrap();

        let on_disk = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert!(!on_disk.contains(&payload.secret));
        assert!(!on_disk.contains(&base64_encode(payload.secret.as_bytes())));
    }

    #[test]
    fn is_encrypted_file_distinguishes_formats() {
        let enc_path = tmp_path("isenc_true");
        encrypt_to_file(&sample(), &enc_path, "whatever").unwrap();
        assert!(is_encrypted_file(&enc_path));
        let _ = std::fs::remove_file(&enc_path);

        let plain_path = tmp_path("isenc_false");
        std::fs::write(&plain_path, serde_json::to_string(&sample()).unwrap()).unwrap();
        assert!(!is_encrypted_file(&plain_path));
        let _ = std::fs::remove_file(&plain_path);
    }

    #[test]
    fn each_save_uses_a_fresh_salt_and_nonce() {
        let path = tmp_path("freshness");
        let payload = sample();

        encrypt_to_file(&payload, &path, "same passphrase").unwrap();
        let first = std::fs::read_to_string(&path).unwrap();
        encrypt_to_file(&payload, &path, "same passphrase").unwrap();
        let second = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_ne!(first, second);
    }

    #[test]
    fn decrypt_from_file_missing_path_is_io_error() {
        let result: io::Result<Payload> = decrypt_from_file("/nonexistent/path/nope.vault", "x");
        assert!(result.is_err());
    }
}