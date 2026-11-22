use crate::approved_channel::ApprovedChannel;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Outbound-only TCP adapter. No listener, discovery, auto-connect or remote control.
/// The caller must supply an authenticated and locally approved channel.
pub struct OutboundConnection {
    stream: TcpStream,
    channel: ApprovedChannel,
}

impl OutboundConnection {
    pub fn connect(
        address: SocketAddr,
        mut channel: ApprovedChannel,
        timeout: Duration,
    ) -> io::Result<Self> {
        if timeout.is_zero() || timeout > Duration::from_secs(15) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid timeout"));
        }
        channel.require_approval()?;
        let stream = TcpStream::connect_timeout(&address, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.set_nodelay(true)?;
        Ok(Self { stream, channel })
    }

    pub fn send(&mut self, plaintext: &[u8]) -> io::Result<()> {
        self.channel.send(&mut self.stream, plaintext)
    }

    pub fn receive(&mut self) -> io::Result<Vec<u8>> {
        self.channel.receive(&mut self.stream)
    }

    pub fn close(&mut self) {
        self.channel.close();
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

impl Drop for OutboundConnection {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SessionCipher;
    use crate::session_gate::SessionGate;
    use std::net::TcpListener;
    use std::thread;

    fn channel() -> ApprovedChannel {
        let key = [11u8; 32];
        let transcript = b"authenticated integration fixture";
        ApprovedChannel::new(
            "session-12345678".into(),
            SessionGate::new(),
            SessionCipher::new(&key, transcript).unwrap(),
            SessionCipher::new(&key, transcript).unwrap(),
        ).unwrap()
    }

    #[test]
    fn loopback_transport_denies_data_without_consent() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buffer = [0u8; 1];
            // No plaintext should be written when approval is absent.
            assert_eq!(stream.read(&mut buffer).unwrap(), 0);
        });
        use std::io::Read;
        let mut connection = OutboundConnection::connect(
            address, channel(), Duration::from_secs(2)
        ).unwrap();
        let error = connection.send(b"not authorized").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        connection.close();
        peer.join().unwrap();
    }

    #[test]
    fn refuses_network_connection_before_local_approval() {
        let address: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let error = match OutboundConnection::connect(
            address, channel(), Duration::from_secs(1)
        ) {
            Ok(_) => panic!("unapproved connection unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn rejects_unbounded_connect_timeout() {
        let address: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(OutboundConnection::connect(address, channel(), Duration::from_secs(16)).is_err());
    }
}
