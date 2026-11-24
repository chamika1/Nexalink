# NexaLink pairing v1

## Threat model
Attackers may control the network, replay messages or present malicious QR invitations. Pairing must never grant remote assistance or location access automatically.

## Android manual pairing

An invitation uses `nexalink:pair:1:<label>:<spki>`, where the label and P-256 public key are URL-safe Base64. The label is UTF-8, at most 64 bytes, and the key is DER SubjectPublicKeyInfo. Device fingerprints are SHA-256 hashes of the SPKI, written as uppercase hexadecimal octets separated by colons.

After users compare the full displayed fingerprints through a trusted channel, a verifier issues a random 32-byte nonce as unpadded URL-safe Base64. The signer calculates SHA-256 over UTF-8 `NexaLink manual pairing v1`, a NUL byte, the verifier fingerprint, a NUL byte, the signer fingerprint, a NUL byte and the nonce bytes. The signer signs the UTF-8 domain `NexaLink identity proof v1` plus a NUL byte and that 32-byte hash with SHA256withECDSA. The response is a DER signature encoded as unpadded URL-safe Base64.

The verifier accepts a response only for its outstanding challenge within two minutes, using the inspected peer's public key. A successful challenge is consumed and the verifier can persist that identity locally. Both devices perform their own verification to establish pins in both directions.

## Live sessions

The manual exchange provides identity pins only. A live transport must verify both peers against their stored public keys, establish fresh encrypted-session keys and require explicit approval for individual capabilities.
