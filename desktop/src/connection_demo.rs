use crate::{handshake_replay::HandshakeReplayGuard, wire_handshake};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

fn prompt(label: &str) -> io::Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut response = String::new();
    if io::stdin().read_line(&mut response)? == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "input closed"));
    }
    Ok(response.trim().to_owned())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn fingerprint(key: &[u8]) -> String {
    Sha256::digest(key).iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(":")
}

fn invite_key(invitation: &str) -> io::Result<Vec<u8>> {
    let fields: Vec<_> = invitation.split(':').collect();
    let ["nexalink", "pair", "1", _, encoded] = fields.as_slice() else {
        return Err(invalid("invalid Android invitation"));
    };
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(io::Error::other)?;
    let key = VerifyingKey::from_public_key_der(&bytes).map_err(io::Error::other)?;
    if key.to_public_key_der().map_err(io::Error::other)?.as_bytes() != bytes {
        return Err(invalid("invalid Android identity encoding"));
    }
    Ok(bytes)
}

fn pair_response(identity: &SigningKey, nonce: &str, verifier: &str, signer: &str) -> io::Result<String> {
    let nonce = URL_SAFE_NO_PAD.decode(nonce).map_err(io::Error::other)?;
    if nonce.len() != 32 {
        return Err(invalid("invalid pairing challenge"));
    }
    let mut hash = Sha256::new();
    hash.update(format!("NexaLink manual pairing v1\0{verifier}\0{signer}\0"));
    hash.update(nonce);
    let mut message = b"NexaLink identity proof v1\0".to_vec();
    message.extend_from_slice(&hash.finalize());
    let signature: Signature = identity.sign(&message);
    Ok(URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()))
}

fn pair() -> io::Result<Option<(SigningKey, Vec<u8>)>> {
    let identity = SigningKey::random(&mut OsRng);
    let spki = identity.verifying_key().to_public_key_der().map_err(io::Error::other)?;
    let local_fingerprint = fingerprint(spki.as_bytes());
    println!("Temporary Windows identity for this run.");
    println!("Invitation: nexalink:pair:1:V2luZG93cw:{}", URL_SAFE_NO_PAD.encode(spki.as_bytes()));
    println!("Windows fingerprint: {local_fingerprint}");

    let peer = invite_key(&prompt("Paste the Android invitation: ")?)?;
    let peer_fingerprint = fingerprint(&peer);
    println!("Android fingerprint: {peer_fingerprint}");
    if prompt("Compare the full fingerprints on both devices. Type yes to continue: ")? != "yes" {
        return Ok(None);
    }
    let challenge = prompt("Paste the challenge from Android: ")?;
    println!("Response: {}", pair_response(&identity, &challenge, &peer_fingerprint, &local_fingerprint)?);
    Ok(Some((identity, peer)))
}

pub fn run(address: SocketAddr) -> io::Result<()> {
    let Some((identity, peer)) = pair()? else { return Ok(()) };
    if prompt("Save the verified Windows device on Android. Type listen when ready: ")? != "listen" {
        return Ok(());
    }
    let listener = TcpListener::bind(address)?;
    println!("Waiting for one connection on {}. Press Ctrl+C to stop.", listener.local_addr()?);
    let (mut socket, _) = listener.accept()?;
    drop(listener);
    socket.set_read_timeout(Some(Duration::from_secs(15)))?;
    socket.set_write_timeout(Some(Duration::from_secs(15)))?;
    check_connection(&mut socket, &identity, &peer, false)
}

pub fn run_webrtc(url: &str, create: bool) -> io::Result<()> {
    let Some((identity, peer)) = pair()? else { return Ok(()) };
    let room = if create {
        if prompt("Save the verified device on Android. Type create when ready: ")? != "create" {
            return Ok(());
        }
        None
    } else {
        Some(prompt("Save the verified device on Android, then paste the private room code: ")?)
    };
    let binary = std::env::current_exe()?.with_file_name(if cfg!(windows) {
        "nexalink-rtcbridge.exe"
    } else {
        "nexalink-rtcbridge"
    });
    let mut child = Command::new(binary)
        .args(["-mode", if create { "create" } else { "join" }, "-url", url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let stdin = child.stdin.take().expect("child stdin was piped");
    let stdout = child.stdout.take().expect("child stdout was piped");
    let mut stream = Bridge { child, stdin, stdout };
    if let Some(room) = room {
        writeln!(stream, "{room}")?;
        stream.flush()?;
    }
    check_connection(&mut stream, &identity, &peer, true)
}

struct Bridge {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl Read for Bridge {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        self.stdout.read(data)
    }
}

impl Write for Bridge {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.stdin.write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stdin.flush()
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn check_connection(
    stream: &mut (impl Read + Write),
    identity: &SigningKey,
    peer: &[u8],
    await_ack: bool,
) -> io::Result<()> {
    let mut replay = HandshakeReplayGuard::new(8).map_err(io::Error::other)?;
    let mut channel = wire_handshake::respond(stream, identity, peer, &mut replay, |code| {
        let expected = format!("approve {code}");
        prompt(&format!("Session code {code}. Compare on Android, then type {expected}: "))
            .is_ok_and(|input| input == expected)
    })?;
    if channel.receive(stream)? != b"nexalink-connection-check-v1" {
        return Err(invalid("invalid connection check"));
    }
    channel.send(stream, b"nexalink-connection-ok-v1")?;
    if await_ack && channel.receive(stream)? != b"nexalink-connection-received-v1" {
        return Err(invalid("invalid connection acknowledgement"));
    }
    channel.close();
    println!("Encrypted connection check passed.");
    Ok(())
}
