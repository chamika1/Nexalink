# NexaLink Envelope v1

Android and Windows use the same JSON fields:
```json
{"version":1,"kind":"hello","session_id":"session-12345678","payload":""}
```

Kinds: hello, pairing_request, pairing_response, encrypted_data, disconnect.

Protocol version 1; session IDs 8–128 characters; payload up to 65,536 UTF-8 bytes.

**Security:** These are plain JSON containers, not encrypted or authenticated transport. The name encrypted_data is only a message kind and does not guarantee encryption. Do not put secrets or personal data in payloads before an authenticated encryption layer exists.

Windows agent is a console scaffold without a network listener, screen capture, input injection, or unattended access.
