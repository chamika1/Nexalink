# Windows companion

The Rust companion can accept one foreground, authenticated connection and return an encrypted connection-check response.

## Check a connection from Android

1. Build the Windows companion with `cargo build --release` from this directory. In PowerShell, run `./target/release/nexalink-windows-agent.exe listen 192.168.1.20:4242`, using the PC's own reachable IPv4 address. Use a trusted network and allow the executable through the Windows firewall on that network if prompted.
2. On Android, open **Devices → Pair a device**, generate an invitation, and paste it into the Windows terminal. Paste the Windows invitation into Android and inspect it. Compare both full fingerprints before confirming them on both devices.
3. On Android, create a challenge and paste it into the terminal. Paste the terminal's signed response into Android and save the verified Windows device. Type `listen` in the terminal.
4. On Android, go back to the device list, choose **Check connection** for the Windows device, and enter the PC IP address and port. Compare both displayed session codes. Type the approval shown in the terminal, then tap **Codes match. Approve check** on Android within 15 seconds.
5. Both devices report whether the encrypted check passed. The companion exits after the attempt.

Keep the terminal open throughout pairing and checking. Each companion run creates a fresh temporary Windows identity, so a restart requires pairing again. Both devices need a route to each other. A local network or a configured VPN can supply that route. The companion does not provide NAT traversal or a relay.

## WebRTC companion preview

Keep `nexalink-rtcbridge.exe` beside `nexalink-windows-agent.exe`. The Windows CI artifact includes both binaries. Use `webrtc-create <https-signaling-url>` to create a room or `webrtc-join <https-signaling-url>` to enter a room created by the other peer. The signaling URL must have a certificate trusted by Windows. Pair the app identity and exchange the private room code before comparing the session code. ICE uses STUN to find a direct route.

The Windows preview supports both WebRTC negotiation roles. The desktop still responds to the NexaLink identity handshake in either role. Android's native WebRTC transport, production signaling hosting, and separate-network device testing are pending. Use the TCP connection check described above for the current Android APK.
