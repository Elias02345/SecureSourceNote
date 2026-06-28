//! Symmetric key hierarchy and authenticated encryption (ROADMAP S3, master §5.6).
//!
//! Zero-knowledge-by-default starts here: content is sealed under keys with an
//! audited AEAD, so neither a local on-disk reader nor (later) the relay server
//! sees plaintext. XChaCha20-Poly1305 has a 192-bit nonce, so fresh random
//! nonces are collision-safe — a nonce is never reused.
//!
//! Key hierarchy: a root [`SymKey`] derives child keys via HKDF-SHA256, so one
//! root secret yields a separated per-store key now and per-workspace /
//! per-document content keys later (sharing — ROADMAP S6).
//!
//! ponytail: device-key wrapping, passkey/OPAQUE auth, recovery material, and
//! key zeroization-on-drop are later S3 sub-steps; this module is the audited
//! primitive they build on. No hand-rolled crypto.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;

const NONCE_LEN: usize = 24;

/// A 256-bit symmetric key.
#[derive(Clone)]
pub struct SymKey([u8; 32]);

impl SymKey {
    /// Generate a fresh key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).expect("OS CSPRNG unavailable");
        SymKey(k)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SymKey(bytes)
    }

    /// Derive a child key for a labelled purpose (HKDF-SHA256). Deterministic:
    /// the same parent and `info` always yield the same child; different `info`
    /// yields an independent key.
    pub fn derive(&self, info: &[u8]) -> SymKey {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        SymKey(okm)
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(&self.0).expect("32-byte key is valid")
    }

    /// Seal plaintext, returning `nonce || ciphertext+tag` with a fresh random nonce.
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).expect("OS CSPRNG unavailable");
        let ct = self
            .cipher()
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .expect("XChaCha20-Poly1305 encryption does not fail for a valid key");
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Open `nonce || ciphertext`. `None` if too short, or if authentication
    /// fails (wrong key, corruption, or tampering).
    pub fn open(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < NONCE_LEN {
            return None;
        }
        let (nonce, ct) = sealed.split_at(NONCE_LEN);
        self.cipher().decrypt(XNonce::from_slice(nonce), ct).ok()
    }

    /// Seal to a hex line — text-safe for the JSONL log (no embedded newlines).
    pub fn seal_line(&self, plaintext: &[u8]) -> String {
        to_hex(&self.seal(plaintext))
    }

    /// Open a hex line produced by [`Self::seal_line`].
    pub fn open_line(&self, line: &str) -> Option<Vec<u8>> {
        self.open(&from_hex(line)?)
    }
}

// Never print key material.
impl std::fmt::Debug for SymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SymKey(redacted)")
    }
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let k = SymKey::generate();
        let pt = b"secret note text";
        assert_eq!(k.open(&k.seal(pt)).as_deref(), Some(&pt[..]));
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = SymKey::from_bytes([1u8; 32]).seal(b"x");
        assert!(SymKey::from_bytes([2u8; 32]).open(&sealed).is_none());
    }

    #[test]
    fn tamper_fails_auth() {
        let k = SymKey::from_bytes([3u8; 32]);
        let mut sealed = k.seal(b"payload");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(k.open(&sealed).is_none());
    }

    #[test]
    fn derive_is_deterministic_and_separated() {
        let root = SymKey::from_bytes([9u8; 32]);
        assert_eq!(root.derive(b"a").0, root.derive(b"a").0);
        assert_ne!(root.derive(b"a").0, root.derive(b"b").0);
        assert_ne!(root.derive(b"a").0, root.0);
    }

    #[test]
    fn nonce_is_fresh_each_seal() {
        let k = SymKey::from_bytes([4u8; 32]);
        assert_ne!(k.seal(b"same"), k.seal(b"same"));
    }

    #[test]
    fn hex_line_roundtrip() {
        let k = SymKey::from_bytes([5u8; 32]);
        assert_eq!(
            k.open_line(&k.seal_line(b"hello")).as_deref(),
            Some(&b"hello"[..])
        );
        assert!(from_hex("xyz").is_none());
        assert!(k.open_line("zz").is_none());
    }
}
