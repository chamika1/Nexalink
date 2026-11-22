# Authenticated session primitives — v1

Status: **library code and unit tests only**. There is no live device-to-device transport or negotiated session.

- SessionTranscript serializes protocol label, session ID, initiator/responder signing public keys and both fresh nonces using length-prefixed binary fields.
- SessionAuthenticator signs the full transcript using the Android Keystore identity and verifies a peer's signature against the public key in the transcript.
- The six-digit comparison code is derived from SHA-256 of the transcript. Compare it through a trusted out-of-band channel; six digits alone are not sufficient for secure authentication.
- SessionConsent grants are denied by default, limited to one hour, capability-specific and revocable.

**Still required before live pairing:** authenticated exchange, ephemeral session encryption key agreement, verified transport identity binding, single-use challenge cache, expiration enforcement, mutual user approvals, safe persistence and revocation propagation.

**Never** interpret a parsed invitation, matching UI code, or an in-memory capability grant as proof of a live secure session. Screen sharing, remote input, location and messaging remain disconnected.
