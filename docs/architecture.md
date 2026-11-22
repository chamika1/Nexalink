# Architecture v0.1

## Platforms
- Android: Kotlin + Jetpack Compose, Room, Android Keystore
- Windows: Rust + Tauri companion agent (planned)
- Transport: WebRTC, with initial VPN-based connectivity considered

## Trust model
- Each device has a unique cryptographic identity.
- Pairing requires QR exchange and verification.
- Remote assistance requires explicit approval for each session.
- Location sharing is off by default and revocable.
- No stealth capture, keylogging, or hidden remote control.

## Constraints
- Android screen sharing requires platform consent; arbitrary remote touch control is not generally available.
- NAT traversal may need coordination/relay infrastructure.
- Offline delivery is not guaranteed without a mailbox or online peer.
- No claim of production E2EE until implementation and review.

## Initial acceptance criteria
1. Android app launches with Devices, Chat, Location navigation.
2. No sensitive permissions requested at first launch.
3. Windows companion requires user approval before screen capture.
