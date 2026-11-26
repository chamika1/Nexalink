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

## Internet peer connections

The target is an Android phone on mobile data and a Windows machine on another network. Both devices act as peers and may initiate or accept a session. The connection roles are assigned per session.

Use HTTPS rendezvous to exchange WebRTC offers and answers and ICE to select a network route. Use STUN for direct candidates. Networks that prevent a direct route require either a clear connection failure in direct-only mode or an optional TURN relay. Application frames remain encrypted and require pinned identities and local consent.

The [rendezvous service](../rendezvous/README.md) implements signaling. The Windows preview uses a WebRTC bridge and Android uses a native WebRTC library. Both support creating and joining rooms. Testing across independent networks is pending. The current TCP connection check remains useful for directly reachable addresses.
