# Android client

The Kotlin and Jetpack Compose app opens to Devices, Chat and Location. Build and install the debug APK using the [Android build guide](../docs/android-build.md).

## Pair two Android devices

1. Open **Devices → Pair a device** on both devices. Generate and copy each invitation, then exchange the invitation strings.
2. Paste and inspect the other device’s invitation. Compare each full fingerprint with the one displayed on the originating device in person or over a trusted channel. Check the confirmation box on each device when the fingerprints match.
3. On one device, choose **Create and copy challenge** and send it to the other device. On that device, paste it under **Challenge from peer**, choose **Sign and copy response**, and send the response back.
4. On the first device, paste the signed response and choose **Verify response and save device** within two minutes of creating the challenge. Repeat in the opposite direction so both devices save the verified peer.
5. Open **Back to devices** to see saved devices. To revoke a saved identity, choose **Remove device** and confirm.

Invitation QR codes can be displayed. Exchange text for this workflow. Each device stores its own trust registry. Chat and location are placeholders.
