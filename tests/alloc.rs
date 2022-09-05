#![cfg(feature = "alloc")]

use classic_mceliece_rust::{decapsulate_boxed, encapsulate_boxed, keypair, keypair_boxed};
use classic_mceliece_rust::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};
use std::thread;

/// The smallest amount of stack needed to reliably run the KEM from this library.
const MIN_STACK_SIZE_FOR_THIS_CRATE: usize = (CRYPTO_PUBLICKEYBYTES as f32 * 1.8) as usize;

#[test]
fn to_owned_copies_correct_data() {
    fn run() {
        let mut rng = rand::thread_rng();

        let mut pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk_buf = [0u8; CRYPTO_SECRETKEYBYTES];
        let (_, secret_key) = keypair(&mut pk_buf, &mut sk_buf, &mut rng);

        let secret_key_data = *secret_key.as_array();

        let owned_secret_key = secret_key.to_owned();
        // Make sure the correct data got transferred to the owned variant
        // and that the original was not modified.
        assert_eq!(owned_secret_key.as_array(), &secret_key_data);
        assert_eq!(secret_key.as_array(), &secret_key_data);

        // Make sure the owned version does not get zeroized when the source it was
        // created from goes out of scope.
        drop(secret_key);
        assert_ne!(owned_secret_key.as_array(), &[0; CRYPTO_SECRETKEYBYTES]);

        // Verify that the zeroize feature correctly zeroes out the backing buffer when the feature is
        // active, otherwise not.
        #[cfg(feature = "zeroize")]
        {
            assert_eq!(sk_buf, [0; CRYPTO_SECRETKEYBYTES]);
        }
        #[cfg(not(feature = "zeroize"))]
        {
            assert_eq!(sk_buf, secret_key_data);
        }
    }

    thread::Builder::new()
        // Use a large enough stack size to run all kem variants with the key buffers on the stack.
        .stack_size(4 * 1024 * 1024)
        .spawn(run)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn boxed_versions_dont_trash_the_stack() {
    fn run() {
        let mut rng = rand::thread_rng();

        let (public_key, secret_key) = keypair_boxed(&mut rng);
        let (ciphertext, shared_secret_bob) = encapsulate_boxed(&public_key, &mut rng);
        let shared_secret_alice = decapsulate_boxed(&ciphertext, &secret_key);
        assert_eq!(shared_secret_bob.as_array(), shared_secret_alice.as_array());
    }

    thread::Builder::new()
        .stack_size(MIN_STACK_SIZE_FOR_THIS_CRATE)
        .spawn(run)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn to_owned_not_copying_to_stack() {
    let mut rng = rand::thread_rng();
    let (public_key, _) = keypair_boxed(&mut rng);

    let run = move || {
        let owned_public_key = public_key.to_owned();
        assert_eq!(public_key.as_array(), owned_public_key.as_array());
    };

    thread::Builder::new()
        // Force to_owned to run with a tiny stack.
        .stack_size(16 * 1024)
        .spawn(run)
        .unwrap()
        .join()
        .unwrap();
}
