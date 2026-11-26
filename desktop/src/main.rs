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
    let result = match args.as_slice() {
        [command, address] if command == "listen" => {
            address.parse().map_err(std::io::Error::other).and_then(connection_demo::run)
        }
        [command, url] if command == "webrtc-create" => connection_demo::run_webrtc(url, true),
        [command, url] if command == "webrtc-join" => connection_demo::run_webrtc(url, false),
        _ => {
            println!("Usage: nexalink-windows-agent listen <local-ip:port>");
            println!("       nexalink-windows-agent webrtc-create <https-signaling-url>");
            println!("       nexalink-windows-agent webrtc-join <https-signaling-url>");
            return if args.is_empty() { std::process::ExitCode::SUCCESS } else { std::process::ExitCode::FAILURE };
        }
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Connection check failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
