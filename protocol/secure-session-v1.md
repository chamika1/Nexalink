# Secure session cryptographic primitives (draft)

Status: **Android cryptographic primitives only**. This is not a live or fully authenticated connection.

- Each participant generates a fresh ephemeral P-256 ECDH key pair per session.
- The parties must authenticate the full transcript, including both ephemeral public keys, using long-term identity signatures and out-of-band approval. **This binding is NOT implemented yet.**
- Key derivation: ECDH shared secret; HKDF-Extract using SHA-256(transcript) as salt; HKDF-Expand using HMAC-SHA256 with info ASCII `nexalink-v1-i2r` or `nexalink-v1-r2i` followed by byte 0x01; output 32 bytes.
- AES-256-GCM frame: 8-byte big-endian sequence, 12-byte random nonce, ciphertext and 16-byte tag. AAD = authenticated transcript bytes followed by 8-byte big-endian sequence.
- Receiver rejects duplicate sequence numbers and invalid GCM tags. Current replay tracking is in memory and unbounded; a bounded replay window and session lifecycle must replace it before production use.
- Different send/receive keys MUST be used for each direction; callers select i2r and r2i labels consistently.
- Never send plaintext location, chat or remote input before full mutual authentication, explicit consent and a verified encrypted transport.
- Windows interoperability and end-to-end handshake are not yet implemented.
