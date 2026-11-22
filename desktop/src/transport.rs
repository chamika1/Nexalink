use crate::protocol::Envelope;
use std::io::{self, Read, Write};

/// Length-prefixed JSON framing for a future authenticated transport.
/// This framing is NOT encryption, identity verification, or authorization.
pub const MAX_WIRE_BYTES: usize = 70_000;

pub fn write_envelope<W: Write>(writer: &mut W, message: &Envelope) -> io::Result<()> {
    message.validate().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let bytes = serde_json::to_vec(message)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame too large"));
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()
}

pub fn read_envelope<R: Read>(reader: &mut R) -> io::Result<Envelope> {
    let mut length = [0u8; 4];
    reader.read_exact(&mut length)?;
    let size = u32::from_be_bytes(length) as usize;
    if size == 0 || size > MAX_WIRE_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid frame length"));
    }
    let mut bytes = vec![0u8; size];
    reader.read_exact(&mut bytes)?;
    let message: Envelope = serde_json::from_slice(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    message.validate().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::MessageKind;
    use std::io::Cursor;

    #[test]
    fn two_messages_round_trip() {
        let mut stream = Vec::new();
        let first = Envelope::new(MessageKind::Hello, "session-12345678".into());
        let second = Envelope::new(MessageKind::Disconnect, "session-12345678".into());
        write_envelope(&mut stream, &first).unwrap();
        write_envelope(&mut stream, &second).unwrap();
        let mut reader = Cursor::new(stream);
        assert_eq!(read_envelope(&mut reader).unwrap(), first);
        assert_eq!(read_envelope(&mut reader).unwrap(), second);
    }

    #[test]
    fn reject_oversized_length_before_allocation() {
        let mut reader = Cursor::new((MAX_WIRE_BYTES as u32 + 1).to_be_bytes());
        assert_eq!(read_envelope(&mut reader).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn reject_truncated_frame() {
        let mut reader = Cursor::new(vec![0, 0, 0, 20, b'{']);
        assert_eq!(read_envelope(&mut reader).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn reject_unknown_json_fields() {
        let raw = br#"{"version":1,"kind":"hello","session_id":"session-12345678","payload":"","admin":true}"#;
        let mut wire = (raw.len() as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(raw);
        assert_eq!(read_envelope(&mut Cursor::new(wire)).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
