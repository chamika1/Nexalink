use crate::crypto::SessionCipher;
use crate::secure_frame;
use crate::session_gate::SessionGate;
use std::io::{self, Read, Write};

/// Enforces the local session gate at every send and receive.
/// The caller is responsible for independently verifying the signed handshake
/// before invoking SessionGate::identity_verified. No sockets are opened here.
pub struct ApprovedChannel {
    session_id: String,
    gate: SessionGate,
    outbound: SessionCipher,
    inbound: SessionCipher,
}

impl ApprovedChannel {
    pub fn new(
        session_id: String,
        gate: SessionGate,
        outbound: SessionCipher,
        inbound: SessionCipher,
    ) -> io::Result<Self> {
        if !(8..=128).contains(&session_id.len()) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid session id"));
        }
        Ok(Self { session_id, gate, outbound, inbound })
    }

    pub fn gate_mut(&mut self) -> &mut SessionGate { &mut self.gate }

    /// Fail closed before opening a network socket, not just before sending data.
    pub fn require_approval(&mut self) -> io::Result<()> {
        if self.gate.may_exchange_data() { Ok(()) } else {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "local consent required"))
        }
    }

    pub fn send<W: Write>(&mut self, output: &mut W, plaintext: &[u8]) -> io::Result<()> {
        if !self.gate.may_exchange_data() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "local consent required"));
        }
        secure_frame::send(output, &mut self.outbound, &self.session_id, plaintext)
    }

    pub fn receive<R: Read>(&mut self, input: &mut R) -> io::Result<Vec<u8>> {
        if !self.gate.may_exchange_data() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "local consent required"));
        }
        secure_frame::receive(input, &mut self.inbound, &self.session_id)
    }

    pub fn close(&mut self) { self.gate.revoke(); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::Duration;

    fn channel() -> ApprovedChannel {
        let key = [42u8; 32];
        let transcript = b"authenticated transcript fixture";
        ApprovedChannel::new(
            "session-12345678".to_string(),
            SessionGate::new(),
            SessionCipher::new(&key, transcript).unwrap(),
            SessionCipher::new(&key, transcript).unwrap(),
        ).unwrap()
    }

    #[test]
    fn denies_send_and_receive_without_local_approval() {
        let mut channel = channel();
        let mut wire = Vec::new();
        assert_eq!(channel.send(&mut wire, b"hello").unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(wire.is_empty());
        channel.gate_mut().identity_verified().unwrap();
        assert_eq!(channel.send(&mut wire, b"hello").unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(channel.receive(&mut Cursor::new(Vec::<u8>::new())).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn approved_channel_round_trip_and_revocation() {
        let mut channel = channel();
        channel.gate_mut().identity_verified().unwrap();
        channel.gate_mut().approve_locally(Duration::from_secs(60)).unwrap();
        let mut wire = Vec::new();
        channel.send(&mut wire, b"hello").unwrap();
        assert_eq!(channel.receive(&mut Cursor::new(wire)).unwrap(), b"hello");
        channel.close();
        let mut after_close = Vec::new();
        assert_eq!(channel.send(&mut after_close, b"blocked").unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(after_close.is_empty());
    }

    #[test]
    fn expired_consent_blocks_data() {
        let mut channel = channel();
        channel.gate_mut().identity_verified().unwrap();
        channel.gate_mut().approve_locally(Duration::from_nanos(1)).unwrap();
        assert_eq!(channel.send(&mut Vec::new(), b"blocked").unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }
}
