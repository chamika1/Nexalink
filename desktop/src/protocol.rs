use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_PAYLOAD_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    Hello,
    PairingRequest,
    PairingResponse,
    EncryptedData,
    Disconnect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u8,
    pub kind: MessageKind,
    pub session_id: String,
    pub payload: String,
}

impl Envelope {
    pub fn new(kind: MessageKind, session_id: String) -> Self {
        Self { version: PROTOCOL_VERSION, kind, session_id, payload: String::new() }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != PROTOCOL_VERSION { return Err("unsupported version"); }
        if !(8..=128).contains(&self.session_id.len()) { return Err("invalid session id"); }
        if self.payload.len() > MAX_PAYLOAD_BYTES { return Err("payload too large"); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip() {
        let message = Envelope::new(MessageKind::Hello, "session-12345678".into());
        let json = serde_json::to_string(&message).unwrap();
        let decoded: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(message, decoded);
        assert!(decoded.validate().is_ok());
    }

    #[test]
    fn reject_invalid_version() {
        let mut message = Envelope::new(MessageKind::Hello, "session-12345678".into());
        message.version = 2;
        assert!(message.validate().is_err());
    }

    #[test]
    fn reject_oversized_payload() {
        let mut message = Envelope::new(MessageKind::EncryptedData, "session-12345678".into());
        message.payload = "x".repeat(MAX_PAYLOAD_BYTES + 1);
        assert!(message.validate().is_err());
    }
}
