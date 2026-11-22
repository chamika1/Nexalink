# Encrypted frame adapter v1

An encrypted_data envelope carries unpadded base64url of a SessionCipher frame.
The outer frame is a 4-byte big-endian JSON byte length, followed by the JSON envelope.

Sender: encrypt plaintext with the session's directional AES-256-GCM key and authenticated transcript AAD, base64url-encode the frame, then write the envelope.

Receiver: read bounded envelope, require encrypted_data kind and the expected session ID, base64url-decode and decrypt with the receive-direction key. Reject replayed or tampered ciphertext.

**Not yet a live connection:** No sockets or device discovery are enabled. Callers MUST first verify both device identities, bind both ephemeral keys to a signed handshake transcript, confirm user approval, and derive the correct directional keys. A wire envelope session ID is not authentication.

Do not enable messaging, location, screen streaming or remote control until handshake, consent and integration testing are complete.
