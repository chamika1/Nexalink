# Protocol design

Planned versioned envelopes for device pairing, encrypted chat, consent-based location sharing, and short-lived remote-assistance sessions.

Rules:
- Authenticated peers only.
- No permanent remote-control authorization by default.
- Reject unknown protocol versions and expired sessions.
- Never store raw private keys in the repository.
