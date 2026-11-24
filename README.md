# NexaLink

Local-first, consent-based private device network for **Android and Windows**.

## Planned features
- Encrypted peer-to-peer private messaging
- Opt-in family location sharing
- Android-to-Windows remote desktop assistance with session approval
- Android-to-Android screen sharing with explicit user consent
- Authorized file transfer

## Project status
The Android prototype has Devices, Chat and Location tabs, with manual, verified pairing between Android devices. The Rust companion exercises the encrypted-session protocol in tests.

## Structure
- `android/` — Kotlin and Jetpack Compose client
- `desktop/` — Rust companion prototype
- `protocol/` — versioned peer protocol
- `docs/architecture.md` — trust model, constraints and milestones

## Privacy and security principles
- Local-first storage; no central application database by default
- QR pairing and verified device identity
- Location sharing off by default
- Explicit, revocable approval for screen sharing and remote assistance
- No hidden monitoring, keylogging, or covert remote control
- Network traversal may require signaling, VPN or encrypted relay infrastructure

## Try Android pairing
Build the debug APK using the [Android build guide](docs/android-build.md), then follow the [pairing walkthrough](android/README.md#pair-two-android-devices). The app exchanges pairing data manually and stores verified devices locally. Live messaging, file transfer, location sharing and remote assistance are planned.
