use core::fmt::Debug;

use kem::{
    generic_array::{typenum::U32, GenericArray},
    Decapsulator, EncappedKey, Encapsulator, SharedSecret,
};
use rand::{CryptoRng, RngCore};

use crate::{
    api::CryptoCiphertextBytesTypenum, crypto_kem_dec, crypto_kem_enc, crypto_kem_keypair,
    CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
};

/// A struct for generating ClassicMcEliece keypairs and encapsulating a shared key.
#[derive(Debug)]
pub struct ClassicMcEliece;

impl ClassicMcEliece {
    pub fn keypair<R: CryptoRng + RngCore>(&self, rng: &mut R) -> (SecretKey, PublicKey) {
        let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
        let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];

        crypto_kem_keypair(&mut pk, &mut sk, rng);

        (SecretKey(sk), PublicKey(pk))
    }
}

impl Encapsulator<Ciphertext> for ClassicMcEliece {
    fn try_encap<R: rand::CryptoRng + rand::RngCore>(
        &self,
        csprng: &mut R,
        recip_pubkey: &<Ciphertext as EncappedKey>::RecipientPublicKey,
    ) -> Result<(Ciphertext, SharedSecret<Ciphertext>), kem::Error> {
        let mut ciphertext = [0u8; CRYPTO_CIPHERTEXTBYTES];
        let mut shared_secret = GenericArray::<_, _>::default();
        crypto_kem_enc(
            &mut ciphertext,
            shared_secret.as_mut(),
            &recip_pubkey.0,
            csprng,
        );
        Ok((
            Ciphertext(ciphertext),
            SharedSecret::<Ciphertext>::new(shared_secret),
        ))
    }
}

/// A wrapper wrapping the bytes of a ClassicMcEliece public key.
#[derive(Debug)]
pub struct PublicKey([u8; CRYPTO_PUBLICKEYBYTES]);

/// A wrapper wrapping the bytes of a ClassicMcEliece secret key.
pub struct SecretKey([u8; CRYPTO_SECRETKEYBYTES]);

impl Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SecretKey").field(&"-- redacted --").finish()
    }
}

impl Decapsulator<Ciphertext> for SecretKey {
    fn try_decap(&self, encapped_key: &Ciphertext) -> Result<SharedSecret<Ciphertext>, kem::Error> {
        let mut shared_secret = GenericArray::<_, _>::default();
        if crypto_kem_dec(shared_secret.as_mut(), &encapped_key.0, &self.0) != 0 {
            return Err(kem::Error);
        }
        let res = SharedSecret::<Ciphertext>::new(shared_secret);
        Ok(res)
    }
}

/// A wrapper wrapping the bytes of a ClassicMcEliece ciphertext.
#[derive(Debug)]
pub struct Ciphertext([u8; CRYPTO_CIPHERTEXTBYTES]);

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl EncappedKey for Ciphertext {
    type EncappedKeySize = CryptoCiphertextBytesTypenum;

    type SharedSecretSize = U32;

    type SenderPublicKey = ();

    type RecipientPublicKey = PublicKey;

    fn from_bytes(bytes: &GenericArray<u8, Self::EncappedKeySize>) -> Result<Self, kem::Error> {
        let mut data = [0u8; CRYPTO_CIPHERTEXTBYTES];
        data.copy_from_slice(bytes.as_slice());
        Ok(Ciphertext(data))
    }
}

#[cfg(test)]
mod tests {
    use kem::{Decapsulator, Encapsulator};

    #[test]
    fn test_crypto_kem_api() -> Result<(), kem::Error> {
        use crate::ClassicMcEliece;

        let mut rng_state = crate::nist_aes_rng::AesState::new();

        let (sk, pk) = ClassicMcEliece.keypair(&mut rng_state);

        let (ciphertext, shared_secret) = ClassicMcEliece.try_encap(&mut rng_state, &pk)?;

        let shared_secret2 = sk.try_decap(&ciphertext)?;

        assert_eq!(shared_secret.as_bytes(), shared_secret2.as_bytes());

        Ok(())
    }

    #[test]
    #[cfg(feature = "mceliece8192128f")]
    fn test_crypto_kem_api_keypair() {
        use crate::{
            api::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES},
            ClassicMcEliece,
        };

        let entropy_input = <[u8; 48]>::try_from(
            crate::TestData::new()
                .u8vec("mceliece8192128f_operations_entropy_input")
                .as_slice(),
        )
        .unwrap();

        let compare_sk = crate::TestData::new().u8vec("mceliece8192128f_operations_sk_expected");
        assert_eq!(compare_sk.len(), CRYPTO_SECRETKEYBYTES);

        let compare_pk = crate::TestData::new().u8vec("mceliece8192128f_operations_pk_expected");
        assert_eq!(compare_pk.len(), CRYPTO_PUBLICKEYBYTES);

        let mut rng_state = crate::nist_aes_rng::AesState::new();
        rng_state.randombytes_init(entropy_input);

        let (sk, pk) = ClassicMcEliece.keypair(&mut rng_state);

        assert_eq!(compare_sk, sk.0);
        assert_eq!(compare_pk, pk.0);
    }
}
