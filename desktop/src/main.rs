mod protocol;
mod crypto;
mod transport;
use protocol::{Envelope, MessageKind};

fn main() {
    let hello = Envelope::new(MessageKind::Hello, "local-prototype".into());
    println!("{}", serde_json::to_string_pretty(&hello).expect("serialize hello"));
    println!("NexaLink Windows prototype: no network listener or remote control enabled.");
}
