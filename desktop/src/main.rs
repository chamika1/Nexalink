mod protocol;
mod crypto;
mod transport;
mod secure_frame;
mod session_gate;
mod approved_channel;
mod outbound_connection;
mod handshake_verifier;
mod verified_session;
mod session_transcript;
mod handshake_replay;
mod session_assembly;
mod pairing_registry;
mod wire_handshake;
#[cfg(test)]
mod loopback_integration;
use protocol::{Envelope, MessageKind};

fn main() {
    let hello = Envelope::new(MessageKind::Hello, "local-prototype".into());
    println!("{}", serde_json::to_string_pretty(&hello).expect("serialize hello"));
    println!("NexaLink Windows prototype: no network listener or remote control enabled.");
}
