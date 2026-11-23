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
        match secure_frame::send(output, &mut self.outbound, &self.session_id, plaintext) {
            Ok(()) => Ok(()),
            Err(error) => {
                // A partial write desynchronizes the encrypted stream.
                // Never reuse the advanced cipher sequence after failure.
                self.close();
                Err(error)
            }
        }
    }

    pub fn receive<R: Read>(&mut self, input: &mut R) -> io::Result<Vec<u8>> {
        if !self.gate.may_exchange_data() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "local consent required"));
        }
        match secure_frame::receive(input, &mut self.inbound, &self.session_id) {
            Ok(plaintext) => Ok(plaintext),
            Err(error) => {
                // Any timeout or disconnect can occur after a partial frame read.
                // A malformed, truncated or unauthenticated frame also makes the
                // stream untrustworthy. Require a fresh approved session.
                // All receive failures are terminal. Custom readers may
                // report partial-frame I/O failures as Other, Interrupted,
                // or platform-specific kinds. Continuing would risk frame
                // desynchronization or accepting attacker-controlled bytes.
                self.close();
                Err(error)
            }
        }
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
    fn corrupted_ciphertext_revokes_approval_and_blocks_followup() {
        let mut channel = channel();
        channel.gate_mut().identity_verified().unwrap();
        channel.gate_mut().approve_locally(Duration::from_secs(60)).unwrap();
        let mut wire = Vec::new();
        channel.send(&mut wire, b"authenticated message").unwrap();
        // Preserve valid JSON framing but substitute a different session ID.
        // This is an authenticated transport violation, not a recoverable retry.
        let start = wire.windows(b"session-12345678".len())
            .position(|w| w == b"session-12345678").unwrap();
        wire[start] = b'X';
        assert_eq!(channel.receive(&mut Cursor::new(wire)).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(channel.send(&mut Vec::new(), b"after invalid frame").unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn partial_write_revokes_session_and_prevents_retry() {
        struct FailingWriter { written: usize }
        impl Write for FailingWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.written > 0 {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "disconnect"));
                }
                let count = bytes.len().min(2);
                self.written += count;
                Ok(count)
            }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        let mut channel = channel();
        channel.gate_mut().identity_verified().unwrap();
        channel.gate_mut().approve_locally(Duration::from_secs(60)).unwrap();
        let mut writer = FailingWriter { written: 0 };
        assert_eq!(channel.send(&mut writer, b"message").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe);
        assert_eq!(channel.send(&mut Vec::new(), b"retry").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn partial_read_timeout_revokes_session_and_prevents_retry() {
        struct TimeoutReader { sent: bool }
        impl Read for TimeoutReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if !self.sent {
                    self.sent = true;
                    buf[0] = 0;
                    return Ok(1);
                }
                Err(io::Error::new(io::ErrorKind::TimedOut, "partial frame timeout"))
            }
        }
        let mut channel = channel();
        channel.gate_mut().identity_verified().unwrap();
        channel.gate_mut().approve_locally(Duration::from_secs(60)).unwrap();
        assert_eq!(channel.receive(&mut TimeoutReader { sent: false })
            .unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(channel.send(&mut Vec::new(), b"retry")
            .unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn unknown_io_error_after_partial_frame_revokes_session() {
        struct OtherErrorReader { started: bool }
        impl Read for OtherErrorReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if !self.started {
                    self.started = true;
                    buf[0] = 0;
                    return Ok(1);
                }
                Err(io::Error::new(io::ErrorKind::Other, "unexpected reader failure"))
            }
        }
        let mut channel = channel();
        channel.gate_mut().identity_verified().unwrap();
        channel.gate_mut().approve_locally(Duration::from_secs(60)).unwrap();
        assert_eq!(
            channel.receive(&mut OtherErrorReader { started: false })
                .unwrap_err().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(
            channel.send(&mut Vec::new(), b"must not retry")
                .unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn expired_consent_blocks_data() {
        let mut channel = channel();
        channel.gate_mut().identity_verified().unwrap();
        channel.gate_mut().approve_locally(Duration::from_nanos(1)).unwrap();
        assert_eq!(channel.send(&mut Vec::new(), b"blocked").unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }
}
