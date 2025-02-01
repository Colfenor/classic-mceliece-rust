//! This example tries to mimic a key exchange between two computers over a network.
//! Here the "network" is simulated by simple message passing channels sending heap
//! allocated byte buffers.
#![cfg(feature = "alloc")]

use classic_mceliece_rust::{
    decapsulate_boxed, encapsulate_boxed, keypair_boxed, Ciphertext, PublicKey, SharedSecret,
    CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES,
};
use rand::thread_rng;
use std::sync::mpsc::{self, Sender};
use std::thread;

type Error = Box<dyn std::error::Error>;

fn main() -> Result<(), Error> {
    let mut server_sender = spawn_server();

    let shared_secret1 = run_client(&mut server_sender)?;
    println!(
        "[client] computed shared secret {:?}",
        hex::encode_upper(shared_secret1)
    );

    let shared_secret2 = run_client(&mut server_sender)?;
    println!(
        "[client] computed shared secret {:?}",
        hex::encode_upper(shared_secret2)
    );

    Ok(())
}

fn spawn_server() -> Sender<(Box<[u8]>, Sender<Box<[u8]>>)> {
    // Convert the bytes read from the client into a `PublicKey`
    fn parse_public_key(public_key_data: &mut [u8]) -> Result<PublicKey<'_>, Error> {
        let public_key_array = <&mut [u8; CRYPTO_PUBLICKEYBYTES]>::try_from(public_key_data)?;
        Ok(PublicKey::from(public_key_array))
    }

    fn handle_request(public_key: &mut [u8], response_sender: Sender<Box<[u8]>>) {
        match parse_public_key(public_key) {
            Ok(public_key) => {
                let (ciphertext, shared_secret) = encapsulate_boxed(&public_key, &mut thread_rng());
                println!(
                    "[server] computed shared secret {:?}",
                    hex::encode_upper(shared_secret.as_array())
                );
                let _ = response_sender.send(Box::new(*ciphertext.as_array()));
            }
            Err(e) => eprintln!("[server] Invalid public key: {}", e),
        }
    }

    let (sender, receiver) = mpsc::channel::<(Box<[u8]>, Sender<Box<[u8]>>)>();
    thread::spawn(move || {
        for (mut public_key, response_sender) in receiver.iter() {
            handle_request(&mut public_key, response_sender);
        }
    });
    sender
}

/// Negotiate with `server` and return the shared secret.
fn run_client(
    server: &mut Sender<(Box<[u8]>, Sender<Box<[u8]>>)>,
) -> Result<SharedSecret<'static>, Error> {
    // Convert the bytes read from the server into a `Ciphertext`
    fn parse_ciphertext(ciphertext_data: &[u8]) -> Result<Ciphertext, Error> {
        let ciphertext_array = <[u8; CRYPTO_CIPHERTEXTBYTES]>::try_from(ciphertext_data)?;
        Ok(Ciphertext::from(ciphertext_array))
    }

    let (public_key, secret_key) = keypair_boxed(&mut thread_rng());

    // Send the public key to the server
    let (response_sender, response_receiver) = mpsc::channel();
    server.send((
        public_key.as_array().to_vec().into_boxed_slice(),
        response_sender,
    ))?;

    // Wait for the server to send us the ciphertext back
    let ciphertext_data = response_receiver.recv()?;
    let ciphertext = parse_ciphertext(&ciphertext_data)?;

    // Decapsulate the shared secret
    Ok(decapsulate_boxed(&ciphertext, &secret_key))
}
