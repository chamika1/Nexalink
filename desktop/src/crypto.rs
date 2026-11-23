use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::{Aead, Payload}};
use hkdf::Hkdf;
use p256::{PublicKey, SecretKey, ecdh::diffie_hellman, pkcs8::{DecodePublicKey, EncodePublicKey}};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

/// Draft interoperability primitives; NOT an authenticated transport.
pub struct EphemeralKey {
    secret: SecretKey,
}

impl EphemeralKey {
    pub fn generate() -> Self {
        Self { secret: SecretKey::random(&mut OsRng) }
    }

    pub fn public_key_der(&self) -> Vec<u8> {
        self.secret.public_key().to_public_key_der()
            .expect("P-256 SPKI encoding").as_bytes().to_vec()
    }

    pub fn derive_directional_key(
        &self,
        peer_spki_der: &[u8],
        authenticated_transcript: &[u8],
        initiator_to_responder: bool,
    ) -> Result<[u8; 32], &'static str> {
        if authenticated_transcript.is_empty() || authenticated_transcript.len() > 8192 {
            return Err("invalid transcript");
        }
        let peer = PublicKey::from_public_key_der(peer_spki_der)
            .map_err(|_| "invalid peer P-256 public key")?;
        let secret = diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        let salt = Sha256::digest(authenticated_transcript);
        let hk = Hkdf::<Sha256>::new(Some(&salt), secret.raw_secret_bytes().as_slice());
        let label = if initiator_to_responder {
            b"nexalink-v1-i2r".as_slice()
        } else {
            b"nexalink-v1-r2i".as_slice()
        };
        let mut key = [0u8; 32];
        hk.expand(label, &mut key).map_err(|_| "HKDF expansion failed")?;
        Ok(key)
    }
}

/// Format: big-endian u64 sequence || 12-byte random nonce || ciphertext || GCM tag.
/// Plaintext is capped at 48,000 bytes so base64 encoding of the 36-byte
/// framing/tag overhead stays within protocol::MAX_PAYLOAD_BYTES (65,536).
const MAX_PLAINTEXT_BYTES: usize = 48_000;
/// AAD: transcript bytes || big-endian u64 sequence.
pub struct SessionCipher {
    cipher: Aes256Gcm,
    aad: Vec<u8>,
    next_sequence: u64,
    expected_inbound_sequence: u64,
}

impl SessionCipher {
    pub fn new(key: &[u8; 32], authenticated_transcript: &[u8]) -> Result<Self, &'static str> {
        if authenticated_transcript.is_empty() || authenticated_transcript.len() > 8192 {
            return Err("invalid transcript");
        }
        Ok(Self {
            cipher: Aes256Gcm::new_from_slice(key).map_err(|_| "invalid key")?,
            aad: authenticated_transcript.to_vec(),
            next_sequence: 0,
            expected_inbound_sequence: 0,
        })
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES { return Err("plaintext too large"); }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.checked_add(1).ok_or("sequence exhausted")?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let mut aad = self.aad.clone();
        aad.extend_from_slice(&sequence.to_be_bytes());
        let ciphertext = self.cipher.encrypt(Nonce::from_slice(&nonce_bytes),
            Payload { msg: plaintext, aad: &aad }).map_err(|_| "encryption failed")?;
        let mut frame = Vec::with_capacity(20 + ciphertext.len());
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame.extend_from_slice(&nonce_bytes);
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }

    pub fn decrypt(&mut self, frame: &[u8]) -> Result<Vec<u8>, &'static str> {
        if !(36..=MAX_PLAINTEXT_BYTES + 36).contains(&frame.len()) { return Err("invalid frame length"); }
        let sequence = u64::from_be_bytes(frame[..8].try_into().map_err(|_| "invalid sequence")?);
        // TCP frames must arrive in order. Reject gaps, reordering and replay
        // without retaining an unbounded set of all received sequence numbers.
        if sequence != self.expected_inbound_sequence {
            return Err("out-of-order or replayed sequence");
        }
        let mut aad = self.aad.clone();
        aad.extend_from_slice(&frame[..8]);
        let plaintext = self.cipher.decrypt(Nonce::from_slice(&frame[8..20]),
            Payload { msg: &frame[20..], aad: &aad }).map_err(|_| "authentication failed")?;
        self.expected_inbound_sequence = self.expected_inbound_sequence.checked_add(1)
            .ok_or("inbound sequence exhausted")?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_participants_derive_identical_directional_keys() {
        let alice = EphemeralKey::generate();
        let bob = EphemeralKey::generate();
        let transcript = b"authenticated test transcript";
        let a = alice.derive_directional_key(&bob.public_key_der(), transcript, true).unwrap();
        let b = bob.derive_directional_key(&alice.public_key_der(), transcript, true).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, alice.derive_directional_key(&bob.public_key_der(), transcript, false).unwrap());
    }

    #[test]
    fn tampering_and_replay_are_rejected() {
        let key = [7u8; 32];
        let mut sender = SessionCipher::new(&key, b"transcript").unwrap();
        let mut receiver = SessionCipher::new(&key, b"transcript").unwrap();
        let frame = sender.encrypt(b"hello").unwrap();
        assert_eq!(receiver.decrypt(&frame).unwrap(), b"hello");
        assert!(receiver.decrypt(&frame).is_err());
        let mut altered = sender.encrypt(b"hello").unwrap();
        altered[21] ^= 1;
        assert!(receiver.decrypt(&altered).is_err());
    }

    #[test]
    fn rejects_out_of_order_frames_without_consuming_expected_sequence() {
        let key = [3u8; 32];
        let mut sender = SessionCipher::new(&key, b"ordered transcript").unwrap();
        let mut receiver = SessionCipher::new(&key, b"ordered transcript").unwrap();
        let first = sender.encrypt(b"first").unwrap();
        let second = sender.encrypt(b"second").unwrap();
        assert!(receiver.decrypt(&second).is_err());
        assert_eq!(receiver.decrypt(&first).unwrap(), b"first");
        assert_eq!(receiver.decrypt(&second).unwrap(), b"second");
        assert!(receiver.decrypt(&first).is_err());
    }

    #[test]
    fn maximum_payload_fits_protocol_wire_limits() {
        use crate::protocol::{Envelope, MessageKind, MAX_PAYLOAD_BYTES};
        use crate::transport::write_envelope;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let key = [17u8; 32];
        let mut sender = SessionCipher::new(&key, b"bounded transcript").unwrap();
        let mut receiver = SessionCipher::new(&key, b"bounded transcript").unwrap();
        let plaintext = vec![42u8; MAX_PLAINTEXT_BYTES];
        let frame = sender.encrypt(&plaintext).unwrap();
        let mut envelope = Envelope::new(MessageKind::EncryptedData, "session-12345678".into());
        envelope.payload = URL_SAFE_NO_PAD.encode(&frame);
        assert!(envelope.payload.len() <= MAX_PAYLOAD_BYTES);
        let mut wire = Vec::new();
        write_envelope(&mut wire, &envelope).unwrap();
        assert_eq!(receiver.decrypt(&frame).unwrap(), plaintext);
        assert!(sender.encrypt(&vec![0u8; MAX_PLAINTEXT_BYTES + 1]).is_err());
        assert!(receiver.decrypt(&vec![0u8; MAX_PLAINTEXT_BYTES + 37]).is_err());
    }

    #[test]
    fn wrong_transcript_cannot_decrypt() {
        let key = [8u8; 32];
        let mut sender = SessionCipher::new(&key, b"correct").unwrap();
        let mut receiver = SessionCipher::new(&key, b"incorrect").unwrap();
        assert!(receiver.decrypt(&sender.encrypt(b"hello").unwrap()).is_err());
    }
}
