use crate::crypto::SessionCipher;
use crate::protocol::{Envelope, MessageKind};
use crate::transport::{read_envelope, write_envelope};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::io::{self, Read, Write};

/// Authenticated encryption wrapper for an already-authenticated session.
/// Does not establish trust or open sockets.
pub fn send<W: Write>(
    output: &mut W,
    cipher: &mut SessionCipher,
    session_id: &str,
    plaintext: &[u8],
) -> io::Result<()> {
    let ciphertext = cipher.encrypt(plaintext)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut envelope = Envelope::new(MessageKind::EncryptedData, session_id.to_owned());
    envelope.payload = URL_SAFE_NO_PAD.encode(ciphertext);
    write_envelope(output, &envelope)
}

pub fn receive<R: Read>(
    input: &mut R,
    cipher: &mut SessionCipher,
    expected_session_id: &str,
) -> io::Result<Vec<u8>> {
    let envelope = read_envelope(input)?;
    if envelope.kind != MessageKind::EncryptedData || envelope.session_id != expected_session_id {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected session or kind"));
    }
    let frame = URL_SAFE_NO_PAD.decode(envelope.payload.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid base64"))?;
    cipher.decrypt(&frame)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn encrypted_round_trip_and_replay_rejection() {
        let key = [5u8; 32];
        let mut tx = SessionCipher::new(&key, b"authenticated transcript").unwrap();
        let mut rx = SessionCipher::new(&key, b"authenticated transcript").unwrap();
        let mut wire = Vec::new();
        send(&mut wire, &mut tx, "session-12345678", b"hello").unwrap();
        assert_eq!(receive(&mut Cursor::new(&wire), &mut rx, "session-12345678").unwrap(), b"hello");
        assert!(receive(&mut Cursor::new(&wire), &mut rx, "session-12345678").is_err());
    }

    #[test]
    fn rejects_wrong_session() {
        let key = [5u8; 32];
        let mut tx = SessionCipher::new(&key, b"authenticated transcript").unwrap();
        let mut rx = SessionCipher::new(&key, b"authenticated transcript").unwrap();
        let mut wire = Vec::new();
        send(&mut wire, &mut tx, "session-12345678", b"hello").unwrap();
        assert!(receive(&mut Cursor::new(wire), &mut rx, "session-87654321").is_err());
    }
}
