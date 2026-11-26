# Internet rendezvous

NexaLink's Android and Windows peers use this service to exchange WebRTC connection descriptions. Either device can create a room and initiate the connection. The other device uses the room invitation to answer. The service carries setup messages only. The peers exchange application data over their authenticated WebRTC data channel.

## Run locally

From this directory, run `go run .` with Go 1.22 or newer. The default address is `127.0.0.1:8080`. For an internet test, serve HTTPS with `-listen`, `-tls-cert` and `-tls-key`, or run on loopback behind an HTTPS reverse proxy. Before exposing a shared deployment, configure request rate limits at the proxy and keep room IDs and authorization headers out of access logs.

## Exchange descriptions

1. The initiator sends `POST /rooms` and receives a room ID and two independent bearer tokens. It shares the room ID and responder token privately with the intended peer and keeps the initiator token.
2. The initiator gathers ICE candidates into its offer and sends `PUT /rooms/{id}/offer` with the initiator token and the completed description as the body.
3. The responder uses its token to retrieve the offer with `GET /rooms/{id}/offer`. It gathers ICE candidates into an answer and posts the completed description with `PUT /rooms/{id}/answer`.
4. The initiator uses its token to retrieve the answer with `GET /rooms/{id}/answer`. A valid read returns HTTP 204 while the description is pending and HTTP 200 once it exists. Each description can be published once. Rooms expire after five minutes.

The room credentials grant access only to signaling. Before exchanging user data, both peers must verify the app handshake against their previously pinned device identities and obtain local approval for the requested capability.

## Integration status

The signaling service and its HTTP tests are implemented. The Windows companion and Android app can create or join WebRTC rooms. Physical-device testing across separate networks is pending. Direct internet connections will require ICE with STUN. Some NAT and firewall combinations prevent direct traffic. For those cases, strictly direct mode must report that no route is available. An optional TURN fallback can carry encrypted traffic if relay operation is acceptable.
