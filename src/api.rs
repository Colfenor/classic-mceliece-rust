//! Global constants that are part of the API (i.e. array sizes)

use core::{fmt::Debug, marker::PhantomData};

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

#[cfg(feature = "kem")]
use kem::generic_array::typenum;

use rand::{CryptoRng, RngCore};

use crate::operations::{crypto_kem_dec, crypto_kem_enc, crypto_kem_keypair};

#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
/// The number of bytes required to store the public key
pub const CRYPTO_PUBLICKEYBYTES: usize = 261120;
#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
/// The number of bytes required to store the secret key
pub const CRYPTO_SECRETKEYBYTES: usize = 6492;
#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
/// The number of bytes required to store the ciphertext resulting from the encryption
pub const CRYPTO_CIPHERTEXTBYTES: usize = 128;

#[cfg(all(
    feature = "kem",
    any(feature = "mceliece348864", feature = "mceliece348864f")
))]
/// The number of bytes required to store the ciphertext resulting from the encryption, as a typenum
pub type CryptoCiphertextBytesTypenum = typenum::U128;

#[cfg(feature = "mceliece348864")]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "mceliece348864";
#[cfg(feature = "mceliece348864f")]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "mceliece348864f";

#[cfg(any(feature = "mceliece460896", feature = "mceliece460896f"))]
/// The number of bytes required to store the public key
pub const CRYPTO_PUBLICKEYBYTES: usize = 524160;
#[cfg(any(feature = "mceliece460896", feature = "mceliece460896f"))]
/// The number of bytes required to store the secret key
pub const CRYPTO_SECRETKEYBYTES: usize = 13608;
#[cfg(any(feature = "mceliece460896", feature = "mceliece460896f"))]
/// The number of bytes required to store the ciphertext resulting from the encryption
pub const CRYPTO_CIPHERTEXTBYTES: usize = 188;
#[cfg(all(
    feature = "kem",
    any(feature = "mceliece460896", feature = "mceliece460896f")
))]
/// The number of bytes required to store the ciphertext resulting from the encryption, as a typenum
pub type CryptoCiphertextBytesTypenum = typenum::U188;

#[cfg(feature = "mceliece460896")]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "mceliece460896";
#[cfg(feature = "mceliece460896f")]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "mceliece460896f";

#[cfg(any(feature = "mceliece6688128", feature = "mceliece6688128f"))]
/// The number of bytes required to store the public key
pub const CRYPTO_PUBLICKEYBYTES: usize = 1044992;
#[cfg(any(feature = "mceliece6688128", feature = "mceliece6688128f"))]
/// The number of bytes required to store the secret key
pub const CRYPTO_SECRETKEYBYTES: usize = 13932;
#[cfg(any(feature = "mceliece6688128", feature = "mceliece6688128f"))]
/// The number of bytes required to store the ciphertext resulting from the encryption
pub const CRYPTO_CIPHERTEXTBYTES: usize = 240;
#[cfg(all(
    feature = "kem",
    any(feature = "mceliece6688128", feature = "mceliece6688128f")
))]
/// The number of bytes required to store the ciphertext resulting from the encryption, as a typenum
pub type CryptoCiphertextBytesTypenum = typenum::U240;

#[cfg(feature = "mceliece6688128")]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "mceliece6688128";
#[cfg(feature = "mceliece6688128f")]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "mceliece6688128f";

#[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
/// The number of bytes required to store the public key
pub const CRYPTO_PUBLICKEYBYTES: usize = 1047319;
#[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
/// The number of bytes required to store the secret key
pub const CRYPTO_SECRETKEYBYTES: usize = 13948;
#[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
/// The number of bytes required to store the ciphertext resulting from the encryption
pub const CRYPTO_CIPHERTEXTBYTES: usize = 226;
#[cfg(all(
    feature = "kem",
    any(feature = "mceliece6960119", feature = "mceliece6960119f")
))]
/// The number of bytes required to store the ciphertext resulting from the encryption, as a typenum
pub type CryptoCiphertextBytesTypenum = typenum::U226;

#[cfg(feature = "mceliece6960119")]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "mceliece6960119";
#[cfg(feature = "mceliece6960119f")]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "mceliece6960119f";

#[cfg(any(feature = "mceliece8192128", feature = "mceliece8192128f"))]
/// The number of bytes required to store the public key
pub const CRYPTO_PUBLICKEYBYTES: usize = 1357824;
#[cfg(any(feature = "mceliece8192128", feature = "mceliece8192128f"))]
/// The number of bytes required to store the secret key
pub const CRYPTO_SECRETKEYBYTES: usize = 14120;
#[cfg(any(feature = "mceliece8192128", feature = "mceliece8192128f"))]
/// The number of bytes required to store the ciphertext resulting from the encryption
pub const CRYPTO_CIPHERTEXTBYTES: usize = 240;
#[cfg(all(
    feature = "kem",
    any(feature = "mceliece8192128", feature = "mceliece8192128f")
))]
/// The number of bytes required to store the ciphertext resulting from the encryption, as a typenum
pub type CryptoCiphertextBytesTypenum = typenum::U240;

#[cfg(feature = "mceliece8192128")]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "mceliece8192128";
#[cfg(feature = "mceliece8192128f")]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "mceliece8192128f";

/// The number of bytes required to store the shared secret negotiated between both parties
// this value is uniform
pub const CRYPTO_BYTES: usize = 32;

#[derive(Debug)]
pub struct PublicKey<S: KeyStorage<CRYPTO_PUBLICKEYBYTES>>(S);

impl<S: KeyStorage<CRYPTO_PUBLICKEYBYTES>> PublicKey<S> {
    /// Helper to move a key backed in any possible way to the stack
    pub fn to_owned(&self) -> PublicKey<[u8; CRYPTO_PUBLICKEYBYTES]> {
        PublicKey(*self.0.as_ref())
    }

    /// Helper to move a key backed in any possible way to the heap
    #[cfg(feature = "alloc")]
    pub fn to_heap(&self) -> PublicKey<Box<[u8; CRYPTO_PUBLICKEYBYTES]>> {
        PublicKey(Box::new(*self.0.as_ref()))
    }
}

impl<S: KeyStorage<CRYPTO_PUBLICKEYBYTES>> AsRef<[u8]> for PublicKey<S> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct SecretKey<S: KeyStorage<CRYPTO_SECRETKEYBYTES>>(S);

impl<S: KeyStorage<CRYPTO_SECRETKEYBYTES>> Debug for SecretKey<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SecretKey").field(&"-- redacted --").finish()
    }
}

impl<S: KeyStorage<CRYPTO_SECRETKEYBYTES>> AsRef<[u8]> for SecretKey<S> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<S: KeyStorage<CRYPTO_SECRETKEYBYTES>> SecretKey<S> {
    /// Helper to move a key backed in any possible way to the stack
    pub fn to_owned(&self) -> SecretKey<[u8; CRYPTO_SECRETKEYBYTES]> {
        SecretKey(*self.0.as_ref())
    }

    /// Helper to move a key backed in any possible way to the heap
    #[cfg(feature = "alloc")]
    pub fn to_heap(&self) -> SecretKey<Box<[u8; CRYPTO_SECRETKEYBYTES]>> {
        SecretKey(Box::new(*self.0.as_ref()))
    }
}

pub trait KeyStorage<const SIZE: usize>: Debug {
    fn as_ref(&self) -> &[u8; SIZE];
    fn as_mut(&mut self) -> &mut [u8; SIZE];
}

impl<const SIZE: usize> KeyStorage<SIZE> for [u8; SIZE] {
    fn as_ref(&self) -> &[u8; SIZE] {
        self
    }

    fn as_mut(&mut self) -> &mut [u8; SIZE] {
        self
    }
}

impl<const SIZE: usize> KeyStorage<SIZE> for &mut [u8; SIZE] {
    fn as_ref(&self) -> &[u8; SIZE] {
        self
    }

    fn as_mut(&mut self) -> &mut [u8; SIZE] {
        self
    }
}

#[cfg(feature = "alloc")]
impl<const SIZE: usize> KeyStorage<SIZE> for Box<[u8; SIZE]> {
    fn as_ref(&self) -> &[u8; SIZE] {
        self
    }

    fn as_mut(&mut self) -> &mut [u8; SIZE] {
        self
    }
}

pub fn keypair<
    'a,
    S1: KeyStorage<CRYPTO_SECRETKEYBYTES> + 'a,
    S2: KeyStorage<CRYPTO_PUBLICKEYBYTES> + 'a,
    R: CryptoRng + RngCore,
>(
    mut secret_key_storage: S1,
    mut public_key_storage: S2,
    rng: &mut R,
) -> (SecretKey<S1>, PublicKey<S2>) {
    let pk_buffer = public_key_storage.as_mut();
    let sk_buffer = secret_key_storage.as_mut();

    crypto_kem_keypair(pk_buffer, sk_buffer, rng);

    (SecretKey(secret_key_storage), PublicKey(public_key_storage))
}

#[cfg(feature = "alloc")]
type BoxedPublicKey = PublicKey<Box<[u8; CRYPTO_PUBLICKEYBYTES]>>;
#[cfg(feature = "alloc")]
type BoxedSecretKey = SecretKey<Box<[u8; CRYPTO_SECRETKEYBYTES]>>;

#[cfg(feature = "alloc")]
pub fn keypair_boxed<R: CryptoRng + RngCore>(rng: &mut R) -> (BoxedSecretKey, BoxedPublicKey) {
    let mut sk_buffer = Box::new([0u8; CRYPTO_SECRETKEYBYTES]);
    let mut pk_buffer = Box::new([0u8; CRYPTO_PUBLICKEYBYTES]);

    crypto_kem_keypair(&mut pk_buffer, &mut sk_buffer, rng);

    (SecretKey(sk_buffer), PublicKey(pk_buffer))
}

/// A wrapper wrapping the bytes of a ClassicMcEliece ciphertext.
#[derive(Debug)]
pub struct Ciphertext<S: KeyStorage<CRYPTO_PUBLICKEYBYTES>>(
    [u8; CRYPTO_CIPHERTEXTBYTES],
    PhantomData<S>,
);

impl<S: KeyStorage<CRYPTO_PUBLICKEYBYTES>> AsRef<[u8]> for Ciphertext<S> {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

pub fn encaps<S: KeyStorage<CRYPTO_PUBLICKEYBYTES>, R: CryptoRng + RngCore>(
    pk: &PublicKey<S>,
    rng: &mut R,
) -> (Ciphertext<S>, [u8; CRYPTO_BYTES]) {
    let mut ciphertext_buf = [0u8; CRYPTO_CIPHERTEXTBYTES];
    let mut shared_secret_buf = [0u8; CRYPTO_BYTES];
    crypto_kem_enc(
        &mut ciphertext_buf,
        &mut shared_secret_buf,
        pk.0.as_ref(),
        rng,
    );

    (
        Ciphertext(ciphertext_buf, PhantomData::default()),
        shared_secret_buf,
    )
}

pub fn decaps<S: KeyStorage<CRYPTO_PUBLICKEYBYTES>, T: KeyStorage<CRYPTO_SECRETKEYBYTES>>(
    sk: &SecretKey<T>,
    ciphertext: &Ciphertext<S>,
) -> [u8; CRYPTO_BYTES] {
    let mut shared_secret_buf = [0u8; CRYPTO_BYTES];
    crypto_kem_dec(&mut shared_secret_buf, &ciphertext.0, sk.0.as_ref());

    shared_secret_buf
}

#[cfg(feature = "kem")]
pub(crate) mod kem_api {
    use core::marker::PhantomData;

    use kem::generic_array::{typenum, GenericArray};
    use kem::{Decapsulator, EncappedKey, Encapsulator, SharedSecret};

    use super::{
        crypto_kem_dec, crypto_kem_enc, CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES,
        CRYPTO_SECRETKEYBYTES,
    };

    use super::{Ciphertext, CryptoCiphertextBytesTypenum, KeyStorage, PublicKey, SecretKey};
    /// A struct for generating ClassicMcEliece keypairs and encapsulating a shared key.
    #[derive(Debug)]
    pub struct ClassicMcEliece;

    impl<S: KeyStorage<CRYPTO_PUBLICKEYBYTES>> Encapsulator<Ciphertext<S>> for ClassicMcEliece {
        fn try_encap<R: rand::CryptoRng + rand::RngCore>(
            &self,
            csprng: &mut R,
            recip_pubkey: &<Ciphertext<S> as EncappedKey>::RecipientPublicKey,
        ) -> Result<(Ciphertext<S>, SharedSecret<Ciphertext<S>>), kem::Error> {
            let mut ciphertext = [0u8; CRYPTO_CIPHERTEXTBYTES];
            let mut shared_secret = GenericArray::<_, _>::default();
            crypto_kem_enc(
                &mut ciphertext,
                shared_secret.as_mut(),
                recip_pubkey.0.as_ref(),
                csprng,
            );
            Ok((
                Ciphertext::<S>(ciphertext, PhantomData::default()),
                SharedSecret::<Ciphertext<S>>::new(shared_secret),
            ))
        }
    }

    impl<S: KeyStorage<CRYPTO_PUBLICKEYBYTES>> EncappedKey for Ciphertext<S> {
        type EncappedKeySize = CryptoCiphertextBytesTypenum;

        type SharedSecretSize = typenum::U32;

        type SenderPublicKey = ();

        type RecipientPublicKey = PublicKey<S>;

        fn from_bytes(bytes: &GenericArray<u8, Self::EncappedKeySize>) -> Result<Self, kem::Error> {
            let mut data = [0u8; CRYPTO_CIPHERTEXTBYTES];
            data.copy_from_slice(bytes.as_slice());
            Ok(Ciphertext(data, PhantomData::default()))
        }
    }

    impl<S: KeyStorage<CRYPTO_SECRETKEYBYTES>, T: KeyStorage<CRYPTO_PUBLICKEYBYTES>>
        Decapsulator<Ciphertext<T>> for SecretKey<S>
    {
        fn try_decap(
            &self,
            encapped_key: &Ciphertext<T>,
        ) -> Result<SharedSecret<Ciphertext<T>>, kem::Error> {
            let mut shared_secret = GenericArray::<_, _>::default();
            if crypto_kem_dec(shared_secret.as_mut(), &encapped_key.0, self.0.as_ref()) != 0 {
                return Err(kem::Error);
            }
            let res = SharedSecret::<Ciphertext<T>>::new(shared_secret);
            Ok(res)
        }
    }
    #[cfg(test)]
    mod tests {
        use kem::{Decapsulator, Encapsulator};

        use crate::keypair_boxed;

        #[test]
        fn test_crypto_kem_api() -> Result<(), kem::Error> {
            use crate::ClassicMcEliece;

            let mut rng_state = crate::nist_aes_rng::AesState::new();

            let (sk, pk) = keypair_boxed(&mut rng_state);

            let (ciphertext, shared_secret) = ClassicMcEliece.try_encap(&mut rng_state, &pk)?;

            let shared_secret2 = sk.try_decap(&ciphertext)?;

            assert_eq!(shared_secret.as_bytes(), shared_secret2.as_bytes());

            Ok(())
        }

        #[test]
        #[cfg(feature = "mceliece8192128f")]
        fn test_crypto_kem_api_keypair() {
            use crate::api::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};

            let entropy_input = <[u8; 48]>::try_from(
                crate::TestData::new()
                    .u8vec("mceliece8192128f_operations_entropy_input")
                    .as_slice(),
            )
            .unwrap();

            let compare_sk =
                crate::TestData::new().u8vec("mceliece8192128f_operations_sk_expected");
            assert_eq!(compare_sk.len(), CRYPTO_SECRETKEYBYTES);

            let compare_pk =
                crate::TestData::new().u8vec("mceliece8192128f_operations_pk_expected");
            assert_eq!(compare_pk.len(), CRYPTO_PUBLICKEYBYTES);

            let mut rng_state = crate::nist_aes_rng::AesState::new();
            rng_state.randombytes_init(entropy_input);

            let (sk, pk) = keypair_boxed(&mut rng_state);

            assert_eq!(compare_sk.as_slice(), sk.0.as_ref());
            assert_eq!(compare_pk.as_slice(), pk.0.as_ref());
        }
    }
}
