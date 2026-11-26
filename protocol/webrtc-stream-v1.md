# WebRTC stream v1

Peers exchange complete, non-trickle SDP descriptions through the [HTTPS rendezvous service](../rendezvous/README.md). The SDP is a WebRTC session description JSON object with a `type` of `offer` or `answer` and an `sdp` string. The private invitation combines the room ID and responder token with a period.

The offerer creates an ordered, reliable WebRTC data channel labeled `nexalink-stream-v1`. Each binary data-channel message contains at most 16 KiB. The receiver reads the concatenated bytes as a stream, so message boundaries carry no meaning. STUN is available for direct ICE candidate discovery.

The [NexaLink handshake](session-v1.md) runs on the byte stream. The ICE offerer and application handshake initiator are independent roles. The current desktop companion implements the application responder. The peers authenticate pinned identities and compare the session code before exchanging encrypted data.

For the connection check, the initiator sends the encrypted UTF-8 string `nexalink-connection-check-v1`. The responder replies with `nexalink-connection-ok-v1` and waits for `nexalink-connection-received-v1` before closing the channel.
