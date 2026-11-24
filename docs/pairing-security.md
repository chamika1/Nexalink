# Android pairing security

The Android app generates a P-256 identity in Android Keystore and exports the public key and a device label as invitation text and a QR code. Users independently compare the SHA-256 fingerprints before exchanging manual proof-of-possession challenges.

Each verifier generates a random 32-byte challenge bound to both fingerprints in verifier and signer order. The challenge expires after two minutes on the verifier’s monotonic clock. Successful verification consumes it. Creating a new challenge, changing the invitation or leaving the pairing screen discards the prior challenge. The proof is checked against the public key in the inspected invitation.

A verified identity is stored in the app’s local registry after explicit confirmation. The other device must complete the exchange independently to save its peer. Removing a device deletes its local trust record.

Pairing grants no session capabilities. A future transport must independently authenticate against the stored identity and obtain per-session consent before sending protected data. Android pairing currently uses manual text exchange. Live peer transport and Windows pairing remain prototype work.

See the [Android pairing walkthrough](../android/README.md#pair-two-android-devices) for the user flow.
