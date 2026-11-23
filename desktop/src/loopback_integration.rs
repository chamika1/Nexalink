//! Local-only TCP integration tests for authenticated, consent-gated encrypted frames.
//! Production code still has no inbound listener or automatic remote access.
#[cfg(test)]
mod tests {
    use crate::crypto::EphemeralKey;
    use crate::handshake_replay::HandshakeReplayGuard;
    use crate::session_assembly::{assemble_approved_channel, SignedSession};
    use crate::session_transcript::build_transcript;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::pkcs8::EncodePublicKey;
    use rand_core::OsRng;
    use std::io;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn signed_consented_peers_exchange_encrypted_frames_over_loopback_tcp() {
        let alice_id = SigningKey::random(&mut OsRng);
        let bob_id = SigningKey::random(&mut OsRng);
        let alice_identity = alice_id.verifying_key().to_public_key_der().unwrap();
        let bob_identity = bob_id.verifying_key().to_public_key_der().unwrap();
        let alice_key = EphemeralKey::generate();
        let bob_key = EphemeralKey::generate();
        let alice_public = alice_key.public_key_der();
        let bob_public = bob_key.public_key_der();
        let alice_nonce = [17u8; 32];
        let bob_nonce = [18u8; 32];
        let transcript = build_transcript(
            alice_identity.as_bytes(), bob_identity.as_bytes(),
            &alice_public, &bob_public, &alice_nonce, &bob_nonce,
        ).unwrap();
        let alice_signature: Signature = alice_id.sign(&transcript);
        let bob_signature: Signature = bob_id.sign(&transcript);
        let alice_signature = alice_signature.to_der();
        let bob_signature = bob_signature.to_der();
        let mut alice_replay = HandshakeReplayGuard::new(16).unwrap();
        let mut bob_replay = HandshakeReplayGuard::new(16).unwrap();
        let mut alice = assemble_approved_channel(
            SignedSession {
                session_id: "session-12345678",
                local_ephemeral: &alice_key,
                remote_ephemeral_spki: &bob_public,
                expected_remote_identity_spki: bob_identity.as_bytes(),
                initiator_identity_spki: alice_identity.as_bytes(),
                responder_identity_spki: bob_identity.as_bytes(),
                initiator_ephemeral_spki: &alice_public,
                responder_ephemeral_spki: &bob_public,
                initiator_nonce: &alice_nonce,
                responder_nonce: &bob_nonce,
                local_signature: alice_signature.as_bytes(),
                remote_signature: bob_signature.as_bytes(),
                local_is_initiator: true,
            }, &mut alice_replay, true, Duration::from_secs(60)
        ).unwrap();
        let mut bob = assemble_approved_channel(
            SignedSession {
                session_id: "session-12345678",
                local_ephemeral: &bob_key,
                remote_ephemeral_spki: &alice_public,
                expected_remote_identity_spki: alice_identity.as_bytes(),
                initiator_identity_spki: alice_identity.as_bytes(),
                responder_identity_spki: bob_identity.as_bytes(),
                initiator_ephemeral_spki: &alice_public,
                responder_ephemeral_spki: &bob_public,
                initiator_nonce: &alice_nonce,
                responder_nonce: &bob_nonce,
                local_signature: bob_signature.as_bytes(),
                remote_signature: alice_signature.as_bytes(),
                local_is_initiator: false,
            }, &mut bob_replay, true, Duration::from_secs(60)
        ).unwrap();

        // Listener is test-only, loopback-bound and immediately dropped after use.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let responder = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
            assert_eq!(bob.receive(&mut socket).unwrap(), b"secret from alice");
            bob.send(&mut socket, b"secret from bob").unwrap();
            bob.close();
            assert_eq!(bob.send(&mut socket, b"after revocation").unwrap_err().kind(),
                io::ErrorKind::PermissionDenied);
        });
        let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        alice.send(&mut socket, b"secret from alice").unwrap();
        assert_eq!(alice.receive(&mut socket).unwrap(), b"secret from bob");
        alice.close();
        assert_eq!(alice.send(&mut socket, b"blocked").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied);
        responder.join().unwrap();
    }
}
