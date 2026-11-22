# NexaLink pairing v1 — proposed protocol (NOT DEPLOYED)

## Threat model
Attackers may control the network, replay messages or present malicious QR invitations. Pairing must never grant remote assistance or location access automatically.

## Proposed handshake
1. Each device generates an Android Keystore P-256 signing identity.
2. Invitation includes a version, display label and encoded public signing key. QR content is public.
3. Both parties explicitly initiate a pairing session. A transport is established using an authenticated, encrypted channel (not implemented).
4. Each peer sends a fresh 32-byte nonce and a 2-minute deadline. Nonces must be tracked as single-use.
5. Each peer signs a transcript binding **protocol version, both public keys, both nonces, roles and session identifier**. Both signatures must be verified against the expected public keys.
6. Show a short authentication string derived from the complete signed transcript on both devices. Users compare through a trusted out-of-band channel.
7. Only after both approvals and verified signatures persist the trusted public keys.
8. Every new connection authenticates against stored public keys. Users can revoke a peer; revocation blocks future sessions.

## Current implementation gaps
- No transport, transcript signatures, nonce replay cache, SAS, mutual approval exchange, or live key verification.
- `IdentityProof` signs a domain-separated nonce as a primitive only; it does not yet sign the full transcript.
- `TrustedPeerStore` is a local persistence primitive. Its method name does not imply that callers can skip cryptographic authentication.
- SharedPreferences stores public keys, not private keys or messages; device-local registry can be cleared by app data reset.
- Remote control, screen capture, location sharing and message exchange remain disabled.

Do not expose a UI action that marks a peer trusted solely because an invitation was pasted.
