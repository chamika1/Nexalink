# Transport framing v1 (draft)

Both Android and Windows implement a binary framing primitive:

- Four-byte unsigned big-endian length.
- Exactly that many bytes of UTF-8 JSON Envelope v1.
- Reject zero-length and frames larger than 70,000 bytes **before** allocating a body buffer.
- Reject malformed JSON, unknown kinds, unsupported versions and invalid payloads.
- Multiple frames may be concatenated on a stream.

This is **not a secure channel**. The framing code is deliberately not connected to a network socket or UI. Never send location, messages, secrets or remote-control commands over it in plaintext.

Before using on a network: mutually authenticate identities and ephemeral keys, bind the handshake transcript to session encryption keys, enforce expiration and replay limits, authenticate every frame, and require separate user consent for sensitive capabilities.
