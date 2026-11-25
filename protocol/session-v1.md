# Authenticated session primitives — v1

Status: **cross-platform transcript, key derivation and bounded handshake exchange**. This is not yet a live Android-to-Windows handshake or a production transport.

## Canonical signed transcript

Android and Windows MUST sign the exact same bytes:

- Domain separator: ASCII `nexalink-authenticated-session-v1\0`.
- Six fields, in this order: initiator identity SPKI, responder identity SPKI, initiator ephemeral SPKI, responder ephemeral SPKI, initiator nonce, responder nonce.
- Each field is prefixed by a four-byte unsigned big-endian length. Public keys are non-empty and at most 2,048 bytes; each nonce is exactly 32 bytes; the final transcript is at most 8,192 bytes.
- Identity keys, ephemeral keys and nonces must not be reflected/reused across their respective roles.
- The session ID is carried by the encrypted frame envelope; it is not a transcript field in v1.

## Authentication and encryption

- Both devices sign the canonical transcript using P-256 ECDSA/SHA-256. The remote signing key must match a previously pinned identity; a presented key never pins itself.
- Both sides compare the six-digit SHA-256 comparison code through a trusted out-of-band channel. The code is a confirmation aid, not a replacement for signature and pin verification.
- P-256 ECDH derives directional keys using HKDF-SHA-256 with labels `nexalink-v1-i2r` and `nexalink-v1-r2i`.
- AES-256-GCM frames use big-endian u64 sequence, 12-byte nonce, ciphertext and 16-byte tag. TCP sequence order is strict; replay, reordering, authentication failure or partial I/O must close the session.
- Maximum plaintext is 48,000 bytes to match the Windows wire limit.

## Consent

- Grants are denied by default and scoped to **peer + session + capability**.
- Each capability (chat, location, screen view, remote input) requires a separate local approval. A grant expires within 15 minutes and is revoked when that session closes.
- A grant for one session never authorizes a later connection to the same peer.

## Application integration

Android/Windows transport integration, safe trusted-key persistence on Windows, pairing UI confirmation flow, and cross-language live integration tests are still required. No unattended listener, auto-approval, hidden control, screen capture or remote input is enabled.

## TCP handshake exchange

An initiator sends ASCII `NXL1`, its 32-byte nonce and its ephemeral SPKI. The responder sends the same header with its nonce and ephemeral SPKI, followed by its signature. The initiator verifies the signature against its preselected pin and returns its own signature. SPKIs and DER signatures have two-byte unsigned big-endian length prefixes and maximum lengths of 2,048 and 256 bytes, respectively. Identity SPKIs come from local identity and pairing stores on each side.

Once each side verifies the peer signature, it can show the comparison code for local confirmation. The encrypted frame session ID is the lowercase hexadecimal SHA-256 of the signed transcript. The handshake messages carry no application data. Callers must use dedicated streams with read and write deadlines and close on error or declined confirmation. Application data requires local capability approval.

Android can initiate using its Keystore identity and an existing trusted peer, then reuse the socket for approved chat. Rust supplies a stream responder. Connection UI, the Windows listener and Windows identity persistence are required before a two-device test.
