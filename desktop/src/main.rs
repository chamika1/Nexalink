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
mod connection_demo;

fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if let [command, address] = args.as_slice() {
        if command == "listen" {
            match address.parse().map_err(std::io::Error::other).and_then(connection_demo::run) {
                Ok(()) => return std::process::ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("Connection check failed: {error}");
                    return std::process::ExitCode::FAILURE;
                }
            }
        }
    }
    println!("Usage: nexalink-windows-agent listen <local-ip:port>");
    if args.is_empty() { std::process::ExitCode::SUCCESS } else { std::process::ExitCode::FAILURE }
}
