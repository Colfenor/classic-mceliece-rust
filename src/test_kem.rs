#![cfg(all(test, feature = "kem"))]

use crate::nist_aes_rng::AesState;
use crate::{Ciphertext, CRYPTO_CIPHERTEXTBYTES};
use kem::generic_array::GenericArray;
use kem::{Decapsulator, EncappedKey, Encapsulator};


#[test]
fn crypto_kem_api() -> Result<(), kem::Error> {
    use crate::ClassicMcEliece;

    let mut rng_state = AesState::new();

    let (pk, sk) = crate::keypair_boxed(&mut rng_state);
    let (ciphertext, shared_secret) = ClassicMcEliece.try_encap(&mut rng_state, &pk)?;
    let shared_secret2 = sk.try_decap(&ciphertext)?;

    assert_eq!(shared_secret.as_bytes(), shared_secret2.as_bytes());

    Ok(())
}

#[test]
fn ciphertext_generic_array_length() {
    let ciphertext =
        GenericArray::<u8, <Ciphertext as EncappedKey>::EncappedKeySize>::default();
    assert_eq!(ciphertext.len(), CRYPTO_CIPHERTEXTBYTES);
}

#[test]
fn ciphertext_from_bytes() {
    let mut key_material = GenericArray::<_, _>::default();
    for (i, byte) in key_material.iter_mut().enumerate() {
        *byte = i as u8;
    }
    let ciphertext = <Ciphertext as EncappedKey>::from_bytes(&key_material).unwrap();

    // Verify that the ciphertext contains CRYPTO_CIPHERTEXTBYTES bytes and all with the correct value
    for i in 0..CRYPTO_CIPHERTEXTBYTES {
        assert_eq!(ciphertext.as_array()[i], i as u8)
    }
}