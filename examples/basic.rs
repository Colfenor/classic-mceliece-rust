//! Simple example illustrating shared key negotiation.

use classic_mceliece_rust::{decaps, encaps, keypair};
use classic_mceliece_rust::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};

use rand::thread_rng;

fn main() {
    let mut rng = thread_rng();
    let mut pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk_buf = [0u8; CRYPTO_SECRETKEYBYTES];

    // key generation
    let (sk, pk) = keypair(&mut sk_buf, &mut pk_buf, &mut rng);
    println!("[Alice]\tRunning key generation …");
    println!("[Alice]\tI generated public key {}", hex::encode_upper(&pk));
    println!("[Alice]\tI generated secret key {}", hex::encode_upper(&sk));

    // encapsulation
    let (ct, ss_bob) = encaps(&pk, &mut rng);
    println!("[Bob]\tRunning encapsulation …");
    println!(
        "[Bob]\tI generated shared key {}",
        hex::encode_upper(ss_bob)
    );
    println!("[Bob]\tI generated ciphertext {}", hex::encode_upper(&ct));

    // decapsulation
    let ss_alice = decaps(&sk, &ct);
    println!("[Alice]\tRunning decapsulation …");
    println!(
        "[Alice]\tI decapsulated shared key {}",
        hex::encode_upper(ss_alice)
    );

    if ss_bob != ss_alice {
        eprintln!("\nError: Bob's and Alice's shared key seem to differ.")
    }
}
