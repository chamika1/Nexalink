use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;

/// Verify a signed handshake transcript against an identity pinned by
/// an explicit user-confirmed pairing flow. This alone does NOT grant consent.
pub fn verify_pinned_handshake(
    pinned_identity_spki: &[u8],
    presented_identity_spki: &[u8],
    transcript: &[u8],
    signature_der: &[u8],
) -> bool {
    if pinned_identity_spki.is_empty() || pinned_identity_spki.len() > 2048
        || presented_identity_spki.is_empty() || presented_identity_spki.len() > 2048
        || !(1..=8192).contains(&transcript.len())
        || !(1..=256).contains(&signature_der.len())
        || pinned_identity_spki != presented_identity_spki
    {
        return false;
    }
    let Ok(key) = VerifyingKey::from_public_key_der(presented_identity_spki) else {
        return false;
    };
    let Ok(signature) = Signature::from_der(signature_der) else {
        return false;
    };
    key.verify(transcript, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use p256::pkcs8::EncodePublicKey;
    use rand_core::OsRng;

    #[test]
    fn accepts_only_pinned_identity_and_untampered_transcript() {
        let signer = SigningKey::random(&mut OsRng);
        let other = SigningKey::random(&mut OsRng);
        let spki = signer.verifying_key().to_public_key_der().unwrap();
        let other_spki = other.verifying_key().to_public_key_der().unwrap();
        let transcript = b"nexalink-v1 authenticated transcript fixture";
        let signature: Signature = signer.sign(transcript);
        let der = signature.to_der();
        assert!(verify_pinned_handshake(spki.as_bytes(), spki.as_bytes(), transcript, der.as_bytes()));
        assert!(!verify_pinned_handshake(other_spki.as_bytes(), spki.as_bytes(), transcript, der.as_bytes()));
        assert!(!verify_pinned_handshake(spki.as_bytes(), spki.as_bytes(), b"modified transcript", der.as_bytes()));
        let mut tampered = der.as_bytes().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(!verify_pinned_handshake(spki.as_bytes(), spki.as_bytes(), transcript, &tampered));
    }

    #[test]
    fn rejects_empty_oversized_and_malformed_inputs() {
        assert!(!verify_pinned_handshake(&[], &[], b"x", &[1]));
        assert!(!verify_pinned_handshake(&[1], &[1], &[], &[1]));
        assert!(!verify_pinned_handshake(&[1], &[1], &[2; 8193], &[1]));
        assert!(!verify_pinned_handshake(&[1], &[1], b"x", &[3; 257]));
        assert!(!verify_pinned_handshake(&[1], &[1], b"x", &[1]));
    }
}
