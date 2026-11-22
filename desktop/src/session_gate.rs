use std::time::{Duration, Instant};

/// Session state machine. Transport must never exchange application data
/// before authenticated identities AND explicit local approval are present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Unpaired,
    AwaitingApproval,
    Active,
    Closed,
}

pub struct SessionGate {
    state: State,
    expires_at: Option<Instant>,
    identity_verified: bool,
}

impl SessionGate {
    pub fn new() -> Self {
        Self { state: State::Unpaired, expires_at: None, identity_verified: false }
    }

    pub fn state(&self) -> State { self.state }

    /// Caller must verify signatures and transcript binding before calling.
    pub fn identity_verified(&mut self) -> Result<(), &'static str> {
        if self.state != State::Unpaired { return Err("invalid transition"); }
        self.identity_verified = true;
        self.state = State::AwaitingApproval;
        Ok(())
    }

    /// Approval is local and must be initiated by the person using this device.
    pub fn approve_locally(&mut self, lifetime: Duration) -> Result<(), &'static str> {
        if self.state != State::AwaitingApproval || !self.identity_verified {
            return Err("identity verification required");
        }
        if lifetime.is_zero() || lifetime > Duration::from_secs(15 * 60) {
            return Err("invalid approval lifetime");
        }
        let expires = Instant::now().checked_add(lifetime).ok_or("invalid expiry")?;
        self.expires_at = Some(expires);
        self.state = State::Active;
        Ok(())
    }

    pub fn may_exchange_data(&mut self) -> bool {
        if self.state != State::Active { return false; }
        if !self.identity_verified || !self.expires_at.is_some_and(|t| Instant::now() < t) {
            self.revoke();
            return false;
        }
        true
    }

    pub fn revoke(&mut self) {
        self.state = State::Closed;
        self.expires_at = None;
        self.identity_verified = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cannot_exchange_without_identity_and_approval() {
        let mut gate = SessionGate::new();
        assert!(!gate.may_exchange_data());
        assert!(gate.approve_locally(Duration::from_secs(60)).is_err());
        gate.identity_verified().unwrap();
        assert!(!gate.may_exchange_data());
        gate.approve_locally(Duration::from_secs(60)).unwrap();
        assert!(gate.may_exchange_data());
        gate.revoke();
        assert!(!gate.may_exchange_data());
        assert!(gate.approve_locally(Duration::from_secs(60)).is_err());
    }

    #[test]
    fn rejects_unbounded_or_zero_consent() {
        let mut gate = SessionGate::new();
        gate.identity_verified().unwrap();
        assert!(gate.approve_locally(Duration::ZERO).is_err());
        assert!(gate.approve_locally(Duration::from_secs(901)).is_err());
        assert!(!gate.may_exchange_data());
    }

    #[test]
    fn expired_consent_fails_closed() {
        let mut gate = SessionGate::new();
        gate.identity_verified().unwrap();
        gate.approve_locally(Duration::from_nanos(1)).unwrap();
        assert!(!gate.may_exchange_data());
        assert_eq!(gate.state(), State::Closed);
    }
}
