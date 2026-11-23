use crate::approved_channel::ApprovedChannel;
use crate::crypto::EphemeralKey;
use crate::handshake_replay::HandshakeReplayGuard;
use crate::session_gate::SessionGate;
use crate::verified_session::establish_canonical_verified_ciphers;
use std::io;
use std::time::Duration;

/// Fail-closed session assembly: signatures + ephemeral binding + replay check
/// + explicit local consent must all pass before an ApprovedChannel exists.
/// This module does not open a socket, auto-approve, or grant remote input.
pub struct SignedSession<'a> {
    pub session_id: &'a str,
    pub local_ephemeral: &'a EphemeralKey,
    pub remote_ephemeral_spki: &'a [u8],
    pub initiator_identity_spki: &'a [u8],
    pub responder_identity_spki: &'a [u8],
    pub initiator_ephemeral_spki: &'a [u8],
    pub responder_ephemeral_spki: &'a [u8],
    pub initiator_nonce: &'a [u8; 32],
    pub responder_nonce: &'a [u8; 32],
    pub local_signature: &'a [u8],
    pub remote_signature: &'a [u8],
    pub local_is_initiator: bool,
}

/// Only call after the person operating this device has explicitly approved
/// this peer and this session. The boolean is supplied by trusted local UI,
/// never from a network message.
pub fn assemble_approved_channel(
    session: SignedSession<'_>,
    replay_guard: &mut HandshakeReplayGuard,
    user_approved_locally: bool,
    approval_lifetime: Duration,
) -> io::Result<ApprovedChannel> {
    if !user_approved_locally {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "local approval required"));
    }
    if !(8..=128).contains(&session.session_id.len()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid session id"));
    }
    if approval_lifetime.is_zero() || approval_lifetime > Duration::from_secs(15 * 60) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid consent duration"));
    }
    let transcript = crate::session_transcript::build_transcript(
        session.initiator_identity_spki,
        session.responder_identity_spki,
        session.initiator_ephemeral_spki,
        session.responder_ephemeral_spki,
        session.initiator_nonce,
        session.responder_nonce,
    ).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let (outbound, inbound) = establish_canonical_verified_ciphers(
        session.local_ephemeral,
        session.remote_ephemeral_spki,
        session.initiator_identity_spki,
        session.responder_identity_spki,
        session.initiator_ephemeral_spki,
        session.responder_ephemeral_spki,
        session.initiator_nonce,
        session.responder_nonce,
        session.local_signature,
        session.remote_signature,
        session.local_is_initiator,
    ).map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
    if !replay_guard.accept_verified(&transcript)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))? {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "replayed handshake"));
    }
    let mut gate = SessionGate::new();
    gate.identity_verified().map_err(io::Error::other)?;
    gate.approve_locally(approval_lifetime).map_err(io::Error::other)?;
    ApprovedChannel::new(session.session_id.to_owned(), gate, outbound, inbound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::pkcs8::EncodePublicKey;
    use rand_core::OsRng;

    #[test]
    fn consent_and_replay_gate_signed_encrypted_session() {
        let a_id = SigningKey::random(&mut OsRng);
        let b_id = SigningKey::random(&mut OsRng);
        let a_spki = a_id.verifying_key().to_public_key_der().unwrap();
        let b_spki = b_id.verifying_key().to_public_key_der().unwrap();
        let a = EphemeralKey::generate();
        let b = EphemeralKey::generate();
        let a_pub = a.public_key_der();
        let b_pub = b.public_key_der();
        let na = [9u8; 32];
        let nb = [10u8; 32];
        let transcript = crate::session_transcript::build_transcript(
            a_spki.as_bytes(), b_spki.as_bytes(), &a_pub, &b_pub, &na, &nb
        ).unwrap();
        let a_sig: Signature = a_id.sign(&transcript);
        let b_sig: Signature = b_id.sign(&transcript);
        let a_sig = a_sig.to_der();
        let b_sig = b_sig.to_der();
        let request = || SignedSession {
            session_id: "session-12345678",
            local_ephemeral: &a,
            remote_ephemeral_spki: &b_pub,
            initiator_identity_spki: a_spki.as_bytes(),
            responder_identity_spki: b_spki.as_bytes(),
            initiator_ephemeral_spki: &a_pub,
            responder_ephemeral_spki: &b_pub,
            initiator_nonce: &na,
            responder_nonce: &nb,
            local_signature: a_sig.as_bytes(),
            remote_signature: b_sig.as_bytes(),
            local_is_initiator: true,
        };
        let mut replay = HandshakeReplayGuard::new(32).unwrap();
        assert_eq!(assemble_approved_channel(
            request(), &mut replay, false, Duration::from_secs(60)
        ).err().unwrap().kind(), io::ErrorKind::PermissionDenied);
        let mut channel = assemble_approved_channel(
            request(), &mut replay, true, Duration::from_secs(60)
        ).unwrap();
        let mut bytes = Vec::new();
        channel.send(&mut bytes, b"approved message").unwrap();
        assert!(!bytes.windows(b"approved message".len()).any(|w| w == b"approved message"));
        assert_eq!(assemble_approved_channel(
            request(), &mut replay, true, Duration::from_secs(60)
        ).err().unwrap().kind(), io::ErrorKind::PermissionDenied);
        channel.close();
        assert_eq!(channel.send(&mut Vec::new(), b"blocked").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn rejects_invalid_consent_without_connecting() {
        let mut replay = HandshakeReplayGuard::new(4).unwrap();
        let key = EphemeralKey::generate();
        let nonce = [1u8; 32];
        let request = SignedSession {
            session_id: "session-12345678",
            local_ephemeral: &key,
            remote_ephemeral_spki: &[],
            initiator_identity_spki: &[],
            responder_identity_spki: &[],
            initiator_ephemeral_spki: &[],
            responder_ephemeral_spki: &[],
            initiator_nonce: &nonce,
            responder_nonce: &nonce,
            local_signature: &[],
            remote_signature: &[],
            local_is_initiator: true,
        };
        assert_eq!(assemble_approved_channel(
            request, &mut replay, true, Duration::from_secs(901)
        ).err().unwrap().kind(), io::ErrorKind::InvalidInput);
    }
}
