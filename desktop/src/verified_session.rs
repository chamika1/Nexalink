use crate::crypto::{EphemeralKey, SessionCipher};
use crate::handshake_verifier::verify_pinned_handshake;

/// Construct the canonical transcript from both pinned identities, actual
/// ephemeral public keys and fresh role-specific nonces before verification.
/// The caller must still verify nonce freshness, obtain signatures over these
/// exact bytes, and require explicit local approval before any data exchange.
pub fn establish_canonical_verified_ciphers(
    local_ephemeral: &EphemeralKey,
    remote_ephemeral_spki: &[u8],
    initiator_identity_spki: &[u8],
    responder_identity_spki: &[u8],
    initiator_ephemeral_spki: &[u8],
    responder_ephemeral_spki: &[u8],
    initiator_nonce: &[u8; 32],
    responder_nonce: &[u8; 32],
    local_signature: &[u8],
    remote_signature: &[u8],
    local_is_initiator: bool,
) -> Result<(SessionCipher, SessionCipher), &'static str> {
    let actual_local = local_ephemeral.public_key_der();
    let expected_local = if local_is_initiator {
        initiator_ephemeral_spki
    } else {
        responder_ephemeral_spki
    };
    let expected_remote = if local_is_initiator {
        responder_ephemeral_spki
    } else {
        initiator_ephemeral_spki
    };
    if actual_local.as_slice() != expected_local || remote_ephemeral_spki != expected_remote {
        return Err("ephemeral key does not match signed transcript");
    }
    let transcript = crate::session_transcript::build_transcript(
        initiator_identity_spki, responder_identity_spki,
        initiator_ephemeral_spki, responder_ephemeral_spki,
        initiator_nonce, responder_nonce,
    )?;
    let (local_id, remote_id) = if local_is_initiator {
        (initiator_identity_spki, responder_identity_spki)
    } else {
        (responder_identity_spki, initiator_identity_spki)
    };
    establish_verified_ciphers(
        local_ephemeral, remote_ephemeral_spki, &transcript,
        local_id, local_id, local_signature,
        remote_id, remote_id, remote_signature,
        local_is_initiator,
    )
}

/// Derive directional encryption keys only after verifying both pinned
/// device identities signed the SAME bounded session transcript.
/// Caller must construct the transcript with both ephemeral public keys,
/// fresh nonces, protocol version and explicit initiator/responder roles.
/// This does not grant local consent or open a socket.
pub fn establish_verified_ciphers(
    local_ephemeral: &EphemeralKey,
    remote_ephemeral_spki: &[u8],
    transcript: &[u8],
    local_pinned_identity: &[u8],
    local_presented_identity: &[u8],
    local_signature: &[u8],
    remote_pinned_identity: &[u8],
    remote_presented_identity: &[u8],
    remote_signature: &[u8],
    local_is_initiator: bool,
) -> Result<(SessionCipher, SessionCipher), &'static str> {
    if !(1..=8192).contains(&transcript.len())
        || remote_ephemeral_spki.is_empty()
        || remote_ephemeral_spki.len() > 2048
        || !verify_pinned_handshake(local_pinned_identity, local_presented_identity, transcript, local_signature)
        || !verify_pinned_handshake(remote_pinned_identity, remote_presented_identity, transcript, remote_signature)
    {
        return Err("mutual pinned identity verification failed");
    }
    let outbound_key = local_ephemeral.derive_directional_key(
        remote_ephemeral_spki, transcript, local_is_initiator
    )?;
    let inbound_key = local_ephemeral.derive_directional_key(
        remote_ephemeral_spki, transcript, !local_is_initiator
    )?;
    let outbound = SessionCipher::new(&outbound_key, transcript)?;
    let inbound = SessionCipher::new(&inbound_key, transcript)?;
    Ok((outbound, inbound))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::pkcs8::EncodePublicKey;
    use rand_core::OsRng;

    #[test]
    fn mutually_verified_peers_exchange_directional_ciphertext() {
        let alice_id = SigningKey::random(&mut OsRng);
        let bob_id = SigningKey::random(&mut OsRng);
        let alice_spki = alice_id.verifying_key().to_public_key_der().unwrap();
        let bob_spki = bob_id.verifying_key().to_public_key_der().unwrap();
        let alice = EphemeralKey::generate();
        let bob = EphemeralKey::generate();
        let alice_pub = alice.public_key_der();
        let bob_pub = bob.public_key_der();
        let mut transcript = b"nexalink-v1|initiator|responder|fresh-nonce-a|fresh-nonce-b|".to_vec();
        transcript.extend_from_slice(&alice_pub);
        transcript.extend_from_slice(&bob_pub);
        let alice_sig: Signature = alice_id.sign(&transcript);
        let bob_sig: Signature = bob_id.sign(&transcript);
        let a = alice_sig.to_der();
        let b = bob_sig.to_der();
        let (mut alice_out, mut alice_in) = establish_verified_ciphers(
            &alice, &bob_pub, &transcript,
            alice_spki.as_bytes(), alice_spki.as_bytes(), a.as_bytes(),
            bob_spki.as_bytes(), bob_spki.as_bytes(), b.as_bytes(), true
        ).unwrap();
        let (mut bob_out, mut bob_in) = establish_verified_ciphers(
            &bob, &alice_pub, &transcript,
            bob_spki.as_bytes(), bob_spki.as_bytes(), b.as_bytes(),
            alice_spki.as_bytes(), alice_spki.as_bytes(), a.as_bytes(), false
        ).unwrap();
        assert_eq!(bob_in.decrypt(&alice_out.encrypt(b"hello").unwrap()).unwrap(), b"hello");
        assert_eq!(alice_in.decrypt(&bob_out.encrypt(b"reply").unwrap()).unwrap(), b"reply");
        let wrong = SigningKey::random(&mut OsRng);
        let wrong_spki = wrong.verifying_key().to_public_key_der().unwrap();
        assert!(establish_verified_ciphers(
            &alice, &bob_pub, &transcript,
            alice_spki.as_bytes(), alice_spki.as_bytes(), a.as_bytes(),
            wrong_spki.as_bytes(), bob_spki.as_bytes(), b.as_bytes(), true
        ).is_err());
        let mut altered = transcript.clone();
        altered[0] ^= 1;
        assert!(establish_verified_ciphers(
            &alice, &bob_pub, &altered,
            alice_spki.as_bytes(), alice_spki.as_bytes(), a.as_bytes(),
            bob_spki.as_bytes(), bob_spki.as_bytes(), b.as_bytes(), true
        ).is_err());
    } 
    #[test]
    fn canonical_session_rejects_substituted_ephemeral_key() {
        let alice_id = SigningKey::random(&mut OsRng);
        let bob_id = SigningKey::random(&mut OsRng);
        let alice_spki = alice_id.verifying_key().to_public_key_der().unwrap();
        let bob_spki = bob_id.verifying_key().to_public_key_der().unwrap();
        let alice = EphemeralKey::generate();
        let bob = EphemeralKey::generate();
        let alice_pub = alice.public_key_der();
        let bob_pub = bob.public_key_der();
        let n1 = [1u8; 32];
        let n2 = [2u8; 32];
        let transcript = crate::session_transcript::build_transcript(
            alice_spki.as_bytes(), bob_spki.as_bytes(),
            &alice_pub, &bob_pub, &n1, &n2,
        ).unwrap();
        let a: Signature = alice_id.sign(&transcript);
        let b: Signature = bob_id.sign(&transcript);
        let a = a.to_der();
        let b = b.to_der();
        assert!(establish_canonical_verified_ciphers(
            &alice, &bob_pub, alice_spki.as_bytes(), bob_spki.as_bytes(),
            &alice_pub, &bob_pub, &n1, &n2, a.as_bytes(), b.as_bytes(), true
        ).is_ok());
        let substituted = EphemeralKey::generate().public_key_der();
        assert!(establish_canonical_verified_ciphers(
            &alice, &substituted, alice_spki.as_bytes(), bob_spki.as_bytes(),
            &alice_pub, &bob_pub, &n1, &n2, a.as_bytes(), b.as_bytes(), true
        ).is_err());
        assert!(establish_canonical_verified_ciphers(
            &alice, &bob_pub, alice_spki.as_bytes(), bob_spki.as_bytes(),
            &alice_pub, &bob_pub, &n2, &n1, a.as_bytes(), b.as_bytes(), true
        ).is_err());
    }

}
