/// Canonical, length-delimited transcript for mutual authentication.
/// Both peers MUST sign identical bytes before deriving session keys.
const DOMAIN: &[u8] = b"nexalink-authenticated-session-v1\0";
const MAX_KEY: usize = 2048;

fn append_field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

pub fn build_transcript(
    initiator_identity_spki: &[u8],
    responder_identity_spki: &[u8],
    initiator_ephemeral_spki: &[u8],
    responder_ephemeral_spki: &[u8],
    initiator_nonce: &[u8; 32],
    responder_nonce: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    for key in [
        initiator_identity_spki, responder_identity_spki,
        initiator_ephemeral_spki, responder_ephemeral_spki
    ] {
        if key.is_empty() || key.len() > MAX_KEY {
            return Err("invalid transcript public key length");
        }
    }
    if initiator_identity_spki == responder_identity_spki {
        return Err("same identity on both sides");
    }
    if initiator_ephemeral_spki == responder_ephemeral_spki {
        return Err("same ephemeral key on both sides");
    }
    if initiator_nonce == responder_nonce {
        return Err("identical nonces");
    }
    let mut out = DOMAIN.to_vec();
    for value in [
        initiator_identity_spki, responder_identity_spki,
        initiator_ephemeral_spki, responder_ephemeral_spki,
        initiator_nonce.as_slice(), responder_nonce.as_slice()
    ] {
        append_field(&mut out, value);
    }
    if out.len() > 8192 { return Err("transcript too long"); }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_is_deterministic_and_binds_all_fields() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let base = build_transcript(b"identity-a", b"identity-b", b"ephemeral-a", b"ephemeral-b", &a, &b).unwrap();
        assert_eq!(base, build_transcript(b"identity-a", b"identity-b", b"ephemeral-a", b"ephemeral-b", &a, &b).unwrap());
        assert_ne!(base, build_transcript(b"identity-b", b"identity-a", b"ephemeral-a", b"ephemeral-b", &a, &b).unwrap());
        assert_ne!(base, build_transcript(b"identity-a", b"identity-b", b"ephemeral-b", b"ephemeral-a", &a, &b).unwrap());
        assert_ne!(base, build_transcript(b"identity-a", b"identity-b", b"ephemeral-a", b"ephemeral-b", &b, &a).unwrap());
    }

    #[test]
    fn matches_shared_android_interoperability_vector() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let actual = build_transcript(
            b"alice-id", b"bob-id", b"alice-ephemeral", b"bob-ephemeral", &a, &b
        ).unwrap();
        let mut expected = DOMAIN.to_vec();
        for field in [
            b"alice-id".as_slice(), b"bob-id".as_slice(),
            b"alice-ephemeral".as_slice(), b"bob-ephemeral".as_slice(),
            a.as_slice(), b.as_slice()
        ] {
            expected.extend_from_slice(&(field.len() as u32).to_be_bytes());
            expected.extend_from_slice(field);
        }
        assert_eq!(actual, expected);
    }

    #[test]
    fn reject_reflection_and_malformed_inputs() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert!(build_transcript(b"same", b"same", b"ephemeral-a", b"ephemeral-b", &a, &b).is_err());
        assert!(build_transcript(b"a", b"b", b"same", b"same", &a, &b).is_err());
        assert!(build_transcript(b"a", b"b", b"x", b"y", &a, &a).is_err());
        assert!(build_transcript(b"", b"b", b"x", b"y", &a, &b).is_err());
        assert!(build_transcript(&vec![1u8; 2049], b"b", b"x", b"y", &a, &b).is_err());
    }
}
