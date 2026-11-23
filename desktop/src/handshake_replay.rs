use std::collections::{HashSet, VecDeque};

/// Process-local replay protection for verified handshake transcripts.
/// Construct one registry per application lifetime, NOT per connection.
/// This does not replace persistent anti-replay state across process restarts.
pub struct HandshakeReplayGuard {
    seen: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
    capacity: usize,
}

impl HandshakeReplayGuard {
    pub fn new(capacity: usize) -> Result<Self, &'static str> {
        if !(1..=65_536).contains(&capacity) {
            return Err("invalid replay cache capacity");
        }
        Ok(Self { seen: HashSet::new(), order: VecDeque::new(), capacity })
    }

    /// Record only AFTER mutual signature verification and local consent.
    /// A false result means the exact transcript has already been accepted.
    pub fn accept_verified(&mut self, transcript: &[u8]) -> Result<bool, &'static str> {
        if !(1..=8192).contains(&transcript.len()) {
            return Err("invalid transcript length");
        }
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(transcript).into();
        if self.seen.contains(&digest) {
            return Ok(false);
        }
        if self.order.len() == self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.order.push_back(digest);
        self.seen.insert(digest);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_duplicate_and_allows_distinct_transcripts() {
        let mut guard = HandshakeReplayGuard::new(8).unwrap();
        assert_eq!(guard.accept_verified(b"signed-session-1"), Ok(true));
        assert_eq!(guard.accept_verified(b"signed-session-1"), Ok(false));
        assert_eq!(guard.accept_verified(b"signed-session-2"), Ok(true));
    }

    #[test]
    fn bounded_eviction_and_input_validation() {
        assert!(HandshakeReplayGuard::new(0).is_err());
        assert!(HandshakeReplayGuard::new(65_537).is_err());
        let mut guard = HandshakeReplayGuard::new(2).unwrap();
        assert!(guard.accept_verified(b"").is_err());
        assert!(guard.accept_verified(&[1u8; 8193]).is_err());
        assert_eq!(guard.accept_verified(b"a"), Ok(true));
        assert_eq!(guard.accept_verified(b"b"), Ok(true));
        assert_eq!(guard.accept_verified(b"c"), Ok(true));
        assert_eq!(guard.accept_verified(b"a"), Ok(true)); // evicted, not durable
        assert_eq!(guard.accept_verified(b"c"), Ok(false));
    }
}
