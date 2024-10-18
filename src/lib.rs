#![doc = include_str!("../README.md")]
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod api;
mod benes;
mod bm;
mod controlbits;
mod crypto_hash;
mod decrypt;
mod encrypt;
mod gf;
mod int32_sort;
mod nist_aes_rng;
mod operations;
mod params;
mod pk_gen;
mod root;
mod sk_gen;
mod synd;
mod test_katkem;
mod test_kem;
mod test_utils;
mod transpose;
mod uint64_sort;
mod util;

use core::fmt::Debug;
use rand::{CryptoRng, RngCore};

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::boxed::Box;

#[cfg(feature = "kem")]
pub use kem_api::ClassicMcEliece;

pub use api::{
    CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_PRIMITIVE, CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES,
};

mod macros {
    /// This macro(A, B, C, T) allows to get “&A[B..B+C]” of type “&[T]” as type “&[T; C]”.
    /// The default type T is u8 and “mut A” instead of “A” returns a mutable reference.
    macro_rules! sub {
        ($var:expr, $offset:expr, $len:expr) => {{
            <&[u8; $len]>::try_from(&$var[$offset..($offset + $len)])
                .expect("slice has the correct length")
        }};
        (mut $var:expr, $offset:expr, $len:expr) => {{
            <&mut [u8; $len]>::try_from(&mut $var[$offset..($offset + $len)])
                .expect("slice has the correct length")
        }};
        ($var:expr, $offset:expr, $len:expr, $t:ty) => {{
            <&[$t; $len]>::try_from(&$var[$offset..($offset + $len)])
                .expect("slice has the correct length")
        }};
        (mut $var:expr, $offset:expr, $len:expr, $t:ty) => {{
            <&mut [$t; $len]>::try_from(&mut $var[$offset..($offset + $len)])
                .expect("slice has the correct length")
        }};
    }

    pub(crate) use sub;
}

#[derive(Debug)]
enum KeyBuffer<'a, const SIZE: usize> {
    Borrowed(&'a [u8; SIZE]),
    #[cfg(feature = "alloc")]
    Owned(Box<[u8; SIZE]>),
}

impl<'a, const SIZE: usize> KeyBuffer<'a, SIZE> {
    #[cfg(feature = "alloc")]
    fn to_owned(&self) -> KeyBuffer<'static, SIZE> {
        let mut new_buffer = util::alloc_boxed_array::<SIZE>();
        new_buffer.copy_from_slice(self.as_ref());
        KeyBuffer::Owned(new_buffer)
    }
}

impl<'a, const SIZE: usize> AsRef<[u8; SIZE]> for KeyBuffer<'a, SIZE> {
    fn as_ref(&self) -> &[u8; SIZE] {
        match &self {
            KeyBuffer::Borrowed(buf) => buf,
            #[cfg(feature = "alloc")]
            KeyBuffer::Owned(buf) => buf.as_ref(),
        }
    }
}

#[derive(Debug)]
enum KeyBufferMut<'a, const SIZE: usize> {
    Borrowed(&'a mut [u8; SIZE]),
    #[cfg(feature = "alloc")]
    Owned(Box<[u8; SIZE]>),
}

impl<'a, const SIZE: usize> KeyBufferMut<'a, SIZE> {
    #[cfg(feature = "alloc")]
    fn to_owned(&self) -> KeyBufferMut<'static, SIZE> {
        let mut new_buffer = util::alloc_boxed_array::<SIZE>();
        new_buffer.copy_from_slice(self.as_ref());
        KeyBufferMut::Owned(new_buffer)
    }
}

impl<'a, const SIZE: usize> AsRef<[u8; SIZE]> for KeyBufferMut<'a, SIZE> {
    fn as_ref(&self) -> &[u8; SIZE] {
        match &self {
            KeyBufferMut::Borrowed(buf) => buf,
            #[cfg(feature = "alloc")]
            KeyBufferMut::Owned(buf) => buf.as_ref(),
        }
    }
}

impl<'a, const SIZE: usize> AsMut<[u8; SIZE]> for KeyBufferMut<'a, SIZE> {
    fn as_mut(&mut self) -> &mut [u8; SIZE] {
        match self {
            KeyBufferMut::Borrowed(buf) => buf,
            #[cfg(feature = "alloc")]
            KeyBufferMut::Owned(buf) => buf.as_mut(),
        }
    }
}

#[cfg(feature = "zeroize")]
impl<'a, const SIZE: usize> zeroize::Zeroize for KeyBufferMut<'a, SIZE> {
    fn zeroize(&mut self) {
        match self {
            KeyBufferMut::Borrowed(buf) => buf.zeroize(),
            #[cfg(feature = "alloc")]
            KeyBufferMut::Owned(buf) => buf.zeroize(),
        }
    }
}

/// A Classic McEliece public key. These are very large compared to keys
/// in most other cryptographic algorithms.
#[derive(Debug)]
#[must_use]
pub struct PublicKey<'a>(KeyBuffer<'a, CRYPTO_PUBLICKEYBYTES>);

impl<'a> PublicKey<'a> {
    /// Copies the key to the heap and makes it `'static`.
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[cfg(feature = "alloc")]
    pub fn to_owned(&self) -> PublicKey<'static> {
        PublicKey(self.0.to_owned())
    }

    pub fn as_array(&self) -> &[u8; CRYPTO_PUBLICKEYBYTES] {
        self.0.as_ref()
    }
}

impl<'a> AsRef<[u8]> for PublicKey<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> From<&'a [u8; CRYPTO_PUBLICKEYBYTES]> for PublicKey<'a> {
    fn from(data: &'a [u8; CRYPTO_PUBLICKEYBYTES]) -> Self {
        Self(KeyBuffer::Borrowed(data))
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[cfg(feature = "alloc")]
impl From<Box<[u8; CRYPTO_PUBLICKEYBYTES]>> for PublicKey<'static> {
    fn from(data: Box<[u8; CRYPTO_PUBLICKEYBYTES]>) -> Self {
        Self(KeyBuffer::Owned(data))
    }
}

/// A Classic McEliece secret key.
///
/// Should be kept on the device where it's generated. Used to decapsulate the [`SharedSecret`]
/// from the [`Ciphertext`] received from the encapsulator.
#[must_use]
pub struct SecretKey<'a>(KeyBufferMut<'a, CRYPTO_SECRETKEYBYTES>);

impl<'a> SecretKey<'a> {
    /// Copies the key to the heap and makes it `'static`.
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[cfg(feature = "alloc")]
    pub fn to_owned(&self) -> SecretKey<'static> {
        SecretKey(self.0.to_owned())
    }

    /// Returns the secret key as an array of bytes.
    ///
    /// Please note that depending on your threat model, moving the data out of the
    /// `SecretKey` can be bad for security. The `SecretKey` type is designed to keep the
    /// backing data in a single location in memory and zeroing it out when it goes out
    /// of scope.
    pub fn as_array(&self) -> &[u8; CRYPTO_SECRETKEYBYTES] {
        self.0.as_ref()
    }
}

impl<'a> Debug for SecretKey<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SecretKey").field(&"-- redacted --").finish()
    }
}

impl<'a> AsRef<[u8]> for SecretKey<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> From<&'a mut [u8; CRYPTO_SECRETKEYBYTES]> for SecretKey<'a> {
    /// Represents a mutable byte array of the correct size as a `SecretKey`.
    /// Please note that the array will be zeroed on drop.
    fn from(data: &'a mut [u8; CRYPTO_SECRETKEYBYTES]) -> Self {
        Self(KeyBufferMut::Borrowed(data))
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[cfg(feature = "alloc")]
impl From<Box<[u8; CRYPTO_SECRETKEYBYTES]>> for SecretKey<'static> {
    fn from(data: Box<[u8; CRYPTO_SECRETKEYBYTES]>) -> Self {
        Self(KeyBufferMut::Owned(data))
    }
}

#[cfg(feature = "zeroize")]
impl<'a> zeroize::Zeroize for SecretKey<'a> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<'a> zeroize::ZeroizeOnDrop for SecretKey<'a> {}

impl<'a> Drop for SecretKey<'a> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            self.zeroize();
        }
    }
}

/// The ciphertext computed by the encapsulator.
#[derive(Debug)]
#[must_use]
pub struct Ciphertext([u8; CRYPTO_CIPHERTEXTBYTES]);

impl Ciphertext {
    pub fn as_array(&self) -> &[u8; CRYPTO_CIPHERTEXTBYTES] {
        &self.0
    }
}

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<[u8; CRYPTO_CIPHERTEXTBYTES]> for Ciphertext {
    fn from(data: [u8; CRYPTO_CIPHERTEXTBYTES]) -> Self {
        Self(data)
    }
}

/// The shared secret computed by the KEM. Returned from both the
/// encapsulator and decapsulator.
#[must_use]
pub struct SharedSecret<'a>(KeyBufferMut<'a, CRYPTO_BYTES>);

impl<'a> SharedSecret<'a> {
    /// Copies the secret to the heap and makes it `'static`.
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[cfg(feature = "alloc")]
    pub fn to_owned(&self) -> SharedSecret<'static> {
        SharedSecret(self.0.to_owned())
    }

    pub fn as_array(&self) -> &[u8; CRYPTO_BYTES] {
        self.0.as_ref()
    }
}

impl<'a> Debug for SharedSecret<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SharedSecret")
            .field(&"-- redacted --")
            .finish()
    }
}

impl<'a> AsRef<[u8]> for SharedSecret<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(feature = "zeroize")]
impl<'a> zeroize::Zeroize for SharedSecret<'a> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<'a> zeroize::ZeroizeOnDrop for SharedSecret<'a> {}

impl<'a> Drop for SharedSecret<'a> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            self.zeroize();
        }
    }
}

/// KEM Keypair generation.
///
/// Generate a public and secret key.
/// The public key is meant to be shared with any party,
/// but access to the secret key must be limited to the generating party.
pub fn keypair<'public, 'secret, R: CryptoRng + RngCore>(
    public_key_buf: &'public mut [u8; CRYPTO_PUBLICKEYBYTES],
    secret_key_buf: &'secret mut [u8; CRYPTO_SECRETKEYBYTES],
    rng: &mut R,
) -> (PublicKey<'public>, SecretKey<'secret>) {
    operations::crypto_kem_keypair(public_key_buf, secret_key_buf, rng);

    (
        PublicKey(KeyBuffer::Borrowed(public_key_buf)),
        SecretKey(KeyBufferMut::Borrowed(secret_key_buf)),
    )
}

/// Convenient wrapper around [`keypair`] that stores the public and private keys on the heap
/// and returns them with the ``'static`` lifetime.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn keypair_boxed<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> (PublicKey<'static>, SecretKey<'static>) {
    let mut public_key_buf = util::alloc_boxed_array::<CRYPTO_PUBLICKEYBYTES>();
    let mut secret_key_buf = util::alloc_boxed_array::<CRYPTO_SECRETKEYBYTES>();

    operations::crypto_kem_keypair(&mut public_key_buf, &mut secret_key_buf, rng);

    (
        PublicKey(KeyBuffer::Owned(public_key_buf)),
        SecretKey(KeyBufferMut::Owned(secret_key_buf)),
    )
}

/// KEM Encapsulation.
///
/// Given a public key `public_key`, compute a shared key.
/// The returned ciphertext should be sent back to the entity holding
/// the secret key corresponding to public key given here, so they can compute
/// the same shared key.
pub fn encapsulate<'shared_secret, R: CryptoRng + RngCore>(
    public_key: &PublicKey<'_>,
    shared_secret_buf: &'shared_secret mut [u8; CRYPTO_BYTES],
    rng: &mut R,
) -> (Ciphertext, SharedSecret<'shared_secret>) {
    let mut shared_secret_buf = KeyBufferMut::Borrowed(shared_secret_buf);
    let mut ciphertext_buf = [0u8; CRYPTO_CIPHERTEXTBYTES];

    operations::crypto_kem_enc(
        &mut ciphertext_buf,
        shared_secret_buf.as_mut(),
        public_key.0.as_ref(),
        rng,
    );

    (Ciphertext(ciphertext_buf), SharedSecret(shared_secret_buf))
}

/// Convenient wrapper around [`encapsulate`] that stores the shared secret on the heap
/// and returns it with the ``'static`` lifetime.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn encapsulate_boxed<R: CryptoRng + RngCore>(
    public_key: &PublicKey<'_>,
    rng: &mut R,
) -> (Ciphertext, SharedSecret<'static>) {
    let mut shared_secret_buf = KeyBufferMut::Owned(Box::new([0u8; CRYPTO_BYTES]));
    let mut ciphertext_buf = [0u8; CRYPTO_CIPHERTEXTBYTES];

    operations::crypto_kem_enc(
        &mut ciphertext_buf,
        shared_secret_buf.as_mut(),
        public_key.0.as_ref(),
        rng,
    );

    (Ciphertext(ciphertext_buf), SharedSecret(shared_secret_buf))
}

/// KEM Decapsulation.
///
/// Given a secret key `secret_key` and a ciphertext `ciphertext`,
/// determine the shared key negotiated by both parties.
pub fn decapsulate<'shared_secret>(
    ciphertext: &Ciphertext,
    secret_key: &SecretKey,
    shared_secret_buf: &'shared_secret mut [u8; CRYPTO_BYTES],
) -> SharedSecret<'shared_secret> {
    let mut shared_secret_buf = KeyBufferMut::Borrowed(shared_secret_buf);

    operations::crypto_kem_dec(
        shared_secret_buf.as_mut(),
        ciphertext.as_array(),
        secret_key.as_array(),
    );

    SharedSecret(shared_secret_buf)
}

/// Convenient wrapper around [`decapsulate`] that stores the shared secret on the heap
/// and returns it with the ``'static`` lifetime.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn decapsulate_boxed(ciphertext: &Ciphertext, secret_key: &SecretKey) -> SharedSecret<'static> {
    let mut shared_secret_buf = KeyBufferMut::Owned(Box::new([0u8; CRYPTO_BYTES]));

    operations::crypto_kem_dec(
        shared_secret_buf.as_mut(),
        ciphertext.as_array(),
        secret_key.as_array(),
    );

    SharedSecret(shared_secret_buf)
}

#[cfg(feature = "kem")]
mod kem_api {
    use kem::generic_array::{typenum, GenericArray};
    use kem::{Decapsulator, EncappedKey, Encapsulator, SharedSecret};
    use rand::{CryptoRng, RngCore};

    use crate::{Ciphertext, PublicKey, SecretKey};
    use crate::{CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES};

    /// A struct for encapsulating a shared key using Classic McEliece.
    #[derive(Debug)]
    #[cfg_attr(docsrs, doc(cfg(feature = "kem")))]
    pub struct ClassicMcEliece;

    impl Encapsulator<Ciphertext> for ClassicMcEliece {
        fn try_encap<R: CryptoRng + RngCore>(
            &self,
            csprng: &mut R,
            recip_pubkey: &<Ciphertext as EncappedKey>::RecipientPublicKey,
        ) -> Result<(Ciphertext, SharedSecret<Ciphertext>), kem::Error> {
            let mut ciphertext_buf = [0u8; CRYPTO_CIPHERTEXTBYTES];
            let mut shared_secret = GenericArray::<_, _>::default();

            let shared_secret_buf: &mut [u8; CRYPTO_BYTES] = shared_secret
                .as_mut_slice()
                .try_into()
                .expect("GenericArray should be CRYPTO_BYTES long");

            crate::operations::crypto_kem_enc(
                &mut ciphertext_buf,
                shared_secret_buf,
                recip_pubkey.0.as_ref(),
                csprng,
            );
            Ok((
                Ciphertext(ciphertext_buf),
                SharedSecret::<Ciphertext>::new(shared_secret),
            ))
        }
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "kem")))]
    impl EncappedKey for Ciphertext {
        type EncappedKeySize = crate::api::CryptoCiphertextBytesTypenum;

        type SharedSecretSize = typenum::U32;

        type SenderPublicKey = ();

        type RecipientPublicKey = PublicKey<'static>;

        fn from_bytes(bytes: &GenericArray<u8, Self::EncappedKeySize>) -> Result<Self, kem::Error> {
            let mut data = [0u8; CRYPTO_CIPHERTEXTBYTES];
            data.copy_from_slice(bytes.as_slice());
            Ok(Ciphertext(data))
        }
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "kem")))]
    impl<'sk> Decapsulator<Ciphertext> for SecretKey<'sk> {
        fn try_decap(
            &self,
            ciphertext: &Ciphertext,
        ) -> Result<SharedSecret<Ciphertext>, kem::Error> {
            let mut shared_secret = GenericArray::<_, _>::default();

            let shared_secret_buf: &mut [u8; CRYPTO_BYTES] = shared_secret
                .as_mut_slice()
                .try_into()
                .expect("GenericArray should be CRYPTO_BYTES long");

            crate::operations::crypto_kem_dec(
                shared_secret_buf,
                ciphertext.as_array(),
                self.as_array(),
            );
            Ok(SharedSecret::<Ciphertext>::new(shared_secret))
        }
    }
}

// Tests may use `std`
#[cfg(test)]
#[macro_use]
extern crate std;
