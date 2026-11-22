# NexaLink

Local-first, consent-based private device network for **Android and Windows**.

## Planned features
- Encrypted peer-to-peer private messaging
- Opt-in family location sharing
- Android-to-Windows remote desktop assistance with session approval
- Android-to-Android screen sharing with explicit user consent
- Authorized file transfer

## Project status
**Phase 1: initial architecture and repository scaffold.** This is not yet a runnable application. E2EE and remote-control functionality have not been implemented or audited.

## Structure
- `android/` — Kotlin + Jetpack Compose client (planned)
- `desktop/` — Windows-only Rust/Tauri companion (planned)
- `protocol/` — versioned peer protocol design
- `docs/architecture.md` — trust model, constraints and milestones

## Privacy and security principles
- Local-first storage; no central application database by default
- QR pairing and verified device identity
- Location sharing off by default
- Explicit, revocable approval for screen sharing and remote assistance
- No hidden monitoring, keylogging, or covert remote control
- Network traversal may require signaling, VPN or encrypted relay infrastructure

## Next milestone
Implement an Android Jetpack Compose navigation shell with Devices, Chat and Location screens, then build a Windows companion prototype.
