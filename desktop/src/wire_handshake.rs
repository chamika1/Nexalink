use crate::approved_channel::ApprovedChannel;
use crate::crypto::EphemeralKey;
use crate::handshake_replay::HandshakeReplayGuard;
use crate::handshake_verifier::verify_pinned_handshake;
use crate::session_assembly::{assemble_approved_channel, SignedSession};
use crate::session_transcript::build_transcript;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::time::Duration;

const MAGIC: &[u8; 4] = b"NXL1";

fn read_field(stream: &mut impl Read, max: usize) -> io::Result<Vec<u8>> {
    let mut length = [0; 2];
    stream.read_exact(&mut length)?;
    let length = u16::from_be_bytes(length) as usize;
    if !(1..=max).contains(&length) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid handshake field length"));
    }
    let mut field = vec![0; length];
    stream.read_exact(&mut field)?;
    Ok(field)
}

fn write_field(stream: &mut impl Write, field: &[u8]) -> io::Result<()> {
    stream.write_all(&(field.len() as u16).to_be_bytes())?;
    stream.write_all(field)
}

/// The caller supplies a locally selected identity pin and a dedicated stream with deadlines.
/// On failure the caller must close the stream. The callback must prompt the local operator.
pub fn respond(
    stream: &mut (impl Read + Write),
    identity: &SigningKey,
    pinned_peer: &[u8],
    replay: &mut HandshakeReplayGuard,
    confirm_locally: impl FnOnce(&str) -> bool,
) -> io::Result<ApprovedChannel> {
    p256::ecdsa::VerifyingKey::from_public_key_der(pinned_peer)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid identity pin"))?;
    let local_identity = identity.verifying_key().to_public_key_der().map_err(io::Error::other)?;
    let mut magic = [0; 4];
    stream.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid handshake version"));
    }
    let mut peer_nonce = [0; 32];
    stream.read_exact(&mut peer_nonce)?;
    let peer_ephemeral = read_field(stream, 2048)?;
    p256::PublicKey::from_public_key_der(&peer_ephemeral)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ephemeral public key"))?;

    let ephemeral = EphemeralKey::generate();
    let local_ephemeral = ephemeral.public_key_der();
    let mut nonce = [0; 32];
    OsRng.fill_bytes(&mut nonce);
    let transcript = build_transcript(
        pinned_peer, local_identity.as_bytes(), &peer_ephemeral, &local_ephemeral,
        &peer_nonce, &nonce,
    ).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let signature: Signature = identity.sign(&transcript);
    let signature = signature.to_der();
    stream.write_all(MAGIC)?;
    stream.write_all(&nonce)?;
    write_field(stream, &local_ephemeral)?;
    write_field(stream, signature.as_bytes())?;
    stream.flush()?;

    let peer_signature = read_field(stream, 256)?;
    if !verify_pinned_handshake(pinned_peer, pinned_peer, &transcript, &peer_signature) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "invalid peer signature"));
    }
    let digest = Sha256::digest(&transcript);
    let code = u32::from_be_bytes([0, digest[0], digest[1], digest[2]]) % 1_000_000;
    let session_id = format!("{digest:x}");
    assemble_approved_channel(
        SignedSession {
            session_id: &session_id,
            local_ephemeral: &ephemeral,
            remote_ephemeral_spki: &peer_ephemeral,
            expected_remote_identity_spki: pinned_peer,
            initiator_identity_spki: pinned_peer,
            responder_identity_spki: local_identity.as_bytes(),
            initiator_ephemeral_spki: &peer_ephemeral,
            responder_ephemeral_spki: &local_ephemeral,
            initiator_nonce: &peer_nonce,
            responder_nonce: &nonce,
            local_signature: signature.as_bytes(),
            remote_signature: &peer_signature,
            local_is_initiator: false,
        },
        replay,
        confirm_locally(&format!("{code:06}")),
        Duration::from_secs(60),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn authenticates_android_wire_order_and_receives_encrypted_data() -> io::Result<()> {
        let initiator = SigningKey::random(&mut OsRng);
        let responder = SigningKey::random(&mut OsRng);
        let initiator_pin = initiator.verifying_key().to_public_key_der().unwrap();
        let responder_pin = responder.verifying_key().to_public_key_der().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        let (mut server, _) = listener.accept()?;
        for socket in [&client, &server] {
            socket.set_read_timeout(Some(Duration::from_secs(3)))?;
            socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        }
        let pin = initiator_pin.clone();
        let (send_code, receive_code) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || -> io::Result<Vec<u8>> {
            let mut replay = HandshakeReplayGuard::new(8).unwrap();
            let mut channel = respond(&mut server, &responder, pin.as_bytes(), &mut replay, |code| {
                send_code.send(code.to_owned()).is_ok()
            })?;
            channel.receive(&mut server)
        });
        let mut nonce = [0; 32];
        OsRng.fill_bytes(&mut nonce);
        let ephemeral = EphemeralKey::generate();
        let public = ephemeral.public_key_der();
        client.write_all(MAGIC)?;
        client.write_all(&nonce)?;
        write_field(&mut client, &public)?;
        let mut magic = [0; 4];
        client.read_exact(&mut magic)?;
        assert_eq!(&magic, MAGIC);
        let mut remote_nonce = [0; 32];
        client.read_exact(&mut remote_nonce)?;
        let remote_public = read_field(&mut client, 2048)?;
        let remote_signature = read_field(&mut client, 256)?;
        let transcript = build_transcript(
            initiator_pin.as_bytes(), responder_pin.as_bytes(), &public, &remote_public,
            &nonce, &remote_nonce,
        ).unwrap();
        let signature: Signature = initiator.sign(&transcript);
        let signature = signature.to_der();
        write_field(&mut client, signature.as_bytes())?;
        let digest = Sha256::digest(&transcript);
        let code = u32::from_be_bytes([0, digest[0], digest[1], digest[2]]) % 1_000_000;
        assert_eq!(receive_code.recv_timeout(Duration::from_secs(3)).unwrap(), format!("{code:06}"));
        let mut channel = assemble_approved_channel(
            SignedSession {
                session_id: &format!("{digest:x}"),
                local_ephemeral: &ephemeral,
                remote_ephemeral_spki: &remote_public,
                expected_remote_identity_spki: responder_pin.as_bytes(),
                initiator_identity_spki: initiator_pin.as_bytes(),
                responder_identity_spki: responder_pin.as_bytes(),
                initiator_ephemeral_spki: &public,
                responder_ephemeral_spki: &remote_public,
                initiator_nonce: &nonce,
                responder_nonce: &remote_nonce,
                local_signature: signature.as_bytes(),
                remote_signature: &remote_signature,
                local_is_initiator: true,
            },
            &mut HandshakeReplayGuard::new(8).unwrap(),
            true,
            Duration::from_secs(60),
        )?;
        channel.send(&mut client, b"nexalink wire handshake")?;
        assert_eq!(worker.join().unwrap()?, b"nexalink wire handshake");
        Ok(())
    }

    #[test]
    fn rejects_oversized_field_without_reading_body() {
        let bytes = 2049u16.to_be_bytes();
        assert_eq!(read_field(&mut &bytes[..], 2048).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
