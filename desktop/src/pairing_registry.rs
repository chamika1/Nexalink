//! In-memory trust-on-explicit-pairing registry.
//! A received handshake is never allowed to enroll or replace its own identity.
//! Persistence and QR verification must be implemented by the UI layer.
use std::collections::HashMap;
use std::io;

const MAX_PEERS: usize = 128;
const MAX_LABEL_BYTES: usize = 80;
const MAX_SPKI_BYTES: usize = 2048;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairedPeer {
    pub device_id: String,
    pub display_name: String,
    identity_spki: Vec<u8>,
}

impl PairedPeer {
    pub fn identity_spki(&self) -> &[u8] { &self.identity_spki }
}

#[derive(Default)]
pub struct PairingRegistry {
    peers: HashMap<String, PairedPeer>,
}

impl PairingRegistry {
    pub fn new() -> Self { Self::default() }

    /// Called only after a user verifies the peer identity out of band
    /// (e.g. QR/fingerprint) and confirms pairing in local UI.
    /// Never call from an incoming network request.
    pub fn pair_verified_locally(
        &mut self,
        device_id: &str,
        display_name: &str,
        identity_spki: &[u8],
        user_confirmed: bool,
    ) -> io::Result<()> {
        if !user_confirmed {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "local pairing confirmation required"));
        }
        if device_id.len() < 8 || device_id.len() > 128
            || !device_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || display_name.is_empty() || display_name.len() > MAX_LABEL_BYTES
            || display_name.chars().any(char::is_control)
            || identity_spki.is_empty() || identity_spki.len() > MAX_SPKI_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid pairing data"));
        }
        // No silent key rotation or renaming; the user must unpair first.
        if self.peers.contains_key(device_id) {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "peer already paired; unpair before re-pairing"));
        }
        if self.peers.len() >= MAX_PEERS {
            return Err(io::Error::new(io::ErrorKind::OutOfMemory, "pairing registry full"));
        }
        if self.peers.values().any(|p| p.identity_spki == identity_spki) {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "identity already paired to another device"));
        }
        self.peers.insert(device_id.to_owned(), PairedPeer {
            device_id: device_id.to_owned(),
            display_name: display_name.to_owned(),
            identity_spki: identity_spki.to_vec(),
        });
        Ok(())
    }

    /// Returns only previously trusted key material, never a key supplied by
    /// the remote handshake. Pass this to SignedSession.expected_remote_identity_spki.
    pub fn trusted_identity(&self, device_id: &str) -> io::Result<&[u8]> {
        self.peers.get(device_id)
            .map(|peer| peer.identity_spki())
            .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "device not paired"))
    }

    pub fn unpair_locally(&mut self, device_id: &str, user_confirmed: bool) -> io::Result<()> {
        if !user_confirmed {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "local unpair confirmation required"));
        }
        if self.peers.remove(device_id).is_none() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "device not paired"));
        }
        Ok(())
    }

    pub fn peers(&self) -> impl Iterator<Item = &PairedPeer> { self.peers.values() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_pairing_is_required_before_identity_can_be_used() {
        let mut registry = PairingRegistry::new();
        let id = "device-12345678";
        assert_eq!(registry.trusted_identity(id).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(registry.pair_verified_locally(id, "My PC", b"verified-spki", false)
            .unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        registry.pair_verified_locally(id, "My PC", b"verified-spki", true).unwrap();
        assert_eq!(registry.trusted_identity(id).unwrap(), b"verified-spki");
        assert_eq!(registry.peers().count(), 1);
    }

    #[test]
    fn key_substitution_and_duplicate_identity_fail_closed() {
        let mut registry = PairingRegistry::new();
        registry.pair_verified_locally("device-12345678", "PC", b"original", true).unwrap();
        assert_eq!(registry.pair_verified_locally("device-12345678", "PC", b"attacker", true)
            .unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(registry.pair_verified_locally("device-87654321", "Other", b"original", true)
            .unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(registry.trusted_identity("device-12345678").unwrap(), b"original");
    }

    #[test]
    fn unpair_requires_local_confirmation_and_removes_trust() {
        let mut registry = PairingRegistry::new();
        registry.pair_verified_locally("device-12345678", "PC", b"original", true).unwrap();
        assert_eq!(registry.unpair_locally("device-12345678", false)
            .unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(registry.trusted_identity("device-12345678").is_ok());
        registry.unpair_locally("device-12345678", true).unwrap();
        assert_eq!(registry.trusted_identity("device-12345678").unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        registry.pair_verified_locally("device-12345678", "New PC", b"new-key", true).unwrap();
    }

    #[test]
    fn rejects_malformed_identifiers_and_labels() {
        let mut registry = PairingRegistry::new();
        for id in ["", "../device", "short", "device with spaces"] {
            assert_eq!(registry.pair_verified_locally(id, "PC", b"key", true)
                .unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
        assert!(registry.pair_verified_locally("device-12345678", "bad\nname", b"key", true).is_err());
        assert!(registry.pair_verified_locally("device-12345678", "PC", b"", true).is_err());
    }
}
