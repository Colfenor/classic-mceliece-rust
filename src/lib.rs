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
mod operations;
mod params;
mod pk_gen;
mod root;
mod sk_gen;
mod synd;
mod transpose;
mod uint64_sort;
mod util;

#[cfg(test)]
use alloc::string::{String, ToString};
use core::fmt::Debug;
use rand::{CryptoRng, RngCore};

#[cfg(test)]
use std::io::Write;
#[cfg(test)]
use std::io::{BufRead, BufReader};
#[cfg(test)]
use std::{error, fmt, fs};

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::boxed::Box;

#[cfg(test)]
mod nist_aes_rng;
#[cfg(test)]
use nist_aes_rng::AesState;
#[cfg(test)]
#[macro_use]
extern crate std;
#[cfg(test)]
use std::vec::Vec;

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

    #[cfg(test)]
    mod tests {
        use kem::{Decapsulator, Encapsulator};

        #[test]
        fn test_crypto_kem_api() -> Result<(), kem::Error> {
            use super::ClassicMcEliece;

            let mut rng_state = crate::nist_aes_rng::AesState::new();

            let (pk, sk) = crate::keypair_boxed(&mut rng_state);

            let (ciphertext, shared_secret) = ClassicMcEliece.try_encap(&mut rng_state, &pk)?;

            let shared_secret2 = sk.try_decap(&ciphertext)?;

            assert_eq!(shared_secret.as_bytes(), shared_secret2.as_bytes());

            Ok(())
        }

        #[test]
        #[cfg(feature = "zeroize")]
        fn test_zeroize() {
            use crate::{keypair, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};

            let mut pk_buffer = [0u8; CRYPTO_PUBLICKEYBYTES];
            let mut sk_buffer = [5u8; CRYPTO_SECRETKEYBYTES];
            let mut rng = rand::thread_rng();

            let zeroed_key = [0; CRYPTO_SECRETKEYBYTES];

            let (_, secret_key) = keypair(&mut pk_buffer, &mut sk_buffer, &mut rng);
            drop(secret_key);

            assert_eq!(zeroed_key, sk_buffer);
        }

        #[test]
        #[cfg(feature = "mceliece8192128f")]
        fn test_crypto_kem_api_keypair() {
            use crate::{keypair_boxed, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};

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

            let (pk, sk) = keypair_boxed(&mut rng_state);

            assert_eq!(compare_sk.as_slice(), sk.0.as_ref());
            assert_eq!(compare_pk.as_slice(), pk.0.as_ref());
        }
    }
}

// Test specifics below.
#[cfg(test)]
const KATNUM: usize = 100;

#[derive(Debug)]
#[cfg(test)]
struct InvalidFileFormat(String, usize);

#[cfg(test)]
impl error::Error for InvalidFileFormat {}

#[cfg(test)]
impl fmt::Display for InvalidFileFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "file has invalid format at line {}: {}", self.1, self.0)
    }
}

#[cfg(test)]
pub type R = Result<(), Box<dyn error::Error>>;

#[derive(Debug, PartialEq)]
struct Testcase {
    count: usize,
    seed: [u8; 48],
    pk: [u8; CRYPTO_PUBLICKEYBYTES],
    sk: [u8; CRYPTO_SECRETKEYBYTES],
    ct: [u8; CRYPTO_CIPHERTEXTBYTES],
    ss: [u8; CRYPTO_BYTES],
}

#[cfg(test)]
fn is_zero(x: &[u8]) -> bool {
    for b in x.iter() {
        if *b != 0 {
            return false;
        }
    }

    true
}

#[cfg(test)]
impl Testcase {
    fn new() -> Testcase {
        Testcase {
            count: 0,
            seed: [0u8; 48],
            pk: [0u8; CRYPTO_PUBLICKEYBYTES],
            sk: [0u8; CRYPTO_SECRETKEYBYTES],
            ct: [0u8; CRYPTO_CIPHERTEXTBYTES],
            ss: [0u8; CRYPTO_BYTES],
        }
    }

    fn with_seed(count: usize, seed: &[u8; 48]) -> Testcase {
        Testcase {
            count,
            seed: *seed,
            pk: [0u8; CRYPTO_PUBLICKEYBYTES],
            sk: [0u8; CRYPTO_SECRETKEYBYTES],
            ct: [0u8; CRYPTO_CIPHERTEXTBYTES],
            ss: [0u8; CRYPTO_BYTES],
        }
    }

    fn write_to_file(&self, fd: &mut fs::File) -> R {
        let repr_bytes = |bytes: &[u8]| -> String {
            if is_zero(bytes) {
                "".to_string()
            } else {
                format!(" {}", hex::encode_upper(bytes))
            }
        };

        writeln!(fd, "count = {}", self.count)?;
        writeln!(fd, "seed = {}", hex::encode_upper(self.seed))?;
        writeln!(fd, "pk ={}", repr_bytes(&self.pk).as_str())?;
        writeln!(fd, "sk ={}", repr_bytes(&self.sk).as_str())?;
        writeln!(fd, "ct ={}", repr_bytes(&self.ct).as_str())?;
        writeln!(fd, "ss ={}\n", repr_bytes(&self.ss).as_str())?;

        Ok(())
    }

    /// Parse one line of a `.rsp` file. Returns true if data in the
    /// expected format has been successfully stored in `self`.
    /// Returns false, if the line is empty (acts as record separator).
    fn read_line(&mut self, line: &str, lineno: usize) -> Result<bool, Box<dyn error::Error>> {
        let err = |msg: &str| -> Result<bool, Box<dyn error::Error>> {
            Err(Box::new(InvalidFileFormat(msg.to_string(), lineno)))
        };

        if line.starts_with('#') {
            return Ok(true);
        }
        if line.trim() == "" {
            return Ok(false);
        }

        let mut fields = line.split('=');
        let name = match fields.next() {
            Some(n) => n.trim(),
            None => return err("could not split key with '=' assignment operator"),
        };
        let value = match fields.next() {
            Some(v) => v.trim(),
            None => return err("could not split value with '=' assignment operator"),
        };

        match name {
            "count" => self.count = value.parse::<usize>()?,
            "seed" => hex::decode_to_slice(value, &mut self.seed as &mut [u8])?,
            "pk" => hex::decode_to_slice(value, &mut self.pk as &mut [u8])?,
            "sk" => hex::decode_to_slice(value, &mut self.sk as &mut [u8])?,
            "ct" => hex::decode_to_slice(value, &mut self.ct as &mut [u8])?,
            "ss" => hex::decode_to_slice(value, &mut self.ss as &mut [u8])?,
            _ => return err(&format!("assignment to unknown key '{}'", name)),
        };

        Ok(true)
    }

    fn read_from_file(&mut self, reader: &mut BufReader<fs::File>) -> R {
        for (lineno, line) in reader.lines().enumerate() {
            if !self.read_line(&line?, lineno)? {
                return Ok(());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
impl Eq for Testcase {}

#[cfg(test)]
impl fmt::Display for Testcase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NOTE it requires a new struct with multiple implementations
        //   to abstract Testcase.write_to_file(…) for stdout AND files.
        //   As a result, I decided to duplicate the code.
        let repr_bytes = |bytes: &[u8]| -> String {
            if is_zero(bytes) {
                "".to_string()
            } else {
                format!(" {}", hex::encode_upper(bytes))
            }
        };

        writeln!(f, "count = {}", self.count)?;
        writeln!(f, "seed = {}", hex::encode_upper(self.seed))?;
        writeln!(f, "pk ={}", repr_bytes(&self.pk).as_str())?;
        writeln!(f, "sk ={}", repr_bytes(&self.sk).as_str())?;
        writeln!(f, "ct ={}", repr_bytes(&self.ct).as_str())?;
        writeln!(f, "ss ={}\n", repr_bytes(&self.ss).as_str())
    }
}

#[cfg(test)]
pub fn create_request_file(filepath: &str) -> R {
    let mut fd = fs::File::create(filepath)?;

    // initialize RNG
    let mut entropy_input = [0u8; 48];
    for (i, e) in entropy_input.iter_mut().enumerate() {
        *e = i as u8;
    }
    let mut rng = AesState::new();
    rng.randombytes_init(entropy_input);

    // create KATNUM testcase seeds
    for t in 0..KATNUM {
        let mut tc = Testcase::new();
        tc.count = t;
        rng.fill_bytes(&mut tc.seed);

        tc.write_to_file(&mut fd)?;
    }

    Ok(())
}

#[cfg(test)]
pub fn create_response_file(filepath: &str) -> R {
    let mut fd = fs::File::create(filepath)?;
    writeln!(&mut fd, "# kem/{}\n", CRYPTO_PRIMITIVE)?;

    // initialize RNG
    let mut entropy_input = [0u8; 48];
    for (i, e) in entropy_input.iter_mut().enumerate() {
        *e = i as u8;
    }
    let mut rng = AesState::new();
    rng.randombytes_init(entropy_input);

    // create KATNUM testcase seeds
    for t in 0..KATNUM {
        let mut tc = Testcase::new();
        tc.count = t;
        rng.fill_bytes(&mut tc.seed);

        let mut tc_rng = AesState::new();
        tc_rng.randombytes_init(tc.seed);

        let mut pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk_buf = [0u8; CRYPTO_SECRETKEYBYTES];
        let mut ss_buf1 = [0u8; CRYPTO_BYTES];
        let mut ss_buf2 = [0u8; CRYPTO_BYTES];

        let (pk, sk) = keypair(&mut pk_buf, &mut sk_buf, &mut tc_rng);
        let (ct, ss) = encapsulate(&pk, &mut ss_buf1, &mut tc_rng);
        let ss2 = decapsulate(&ct, &sk, &mut ss_buf2);

        tc.pk = *pk.as_array();
        tc.sk = *sk.as_array();
        assert_eq!(ss.as_array(), ss2.as_array());
        tc.ss = *ss.as_array();
        tc.ct.copy_from_slice(ct.as_ref());
        tc.write_to_file(&mut fd)?;
    }

    Ok(())
}

#[cfg(test)]
pub fn verify(filepath: &str) -> R {
    let fd = fs::File::open(filepath)?;
    let mut reader = BufReader::new(fd);
    let mut rng = AesState::new();

    // first record in a response file is empty (e.g. “# ntruhps2048509\n”)
    // hence, skip it
    let mut expected = Testcase::new();
    expected.read_from_file(&mut reader)?;

    // create KATNUM testcase seeds
    for t in 0..KATNUM {
        let mut expected = Testcase::new();
        expected.read_from_file(&mut reader)?;

        rng.randombytes_init(expected.seed);

        let mut actual = Testcase::with_seed(t, &expected.seed);

        let mut pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk_buf = [0u8; CRYPTO_SECRETKEYBYTES];
        let mut ss_buf1 = [0u8; CRYPTO_BYTES];
        let mut ss_buf2 = [0u8; CRYPTO_BYTES];

        let (pk, sk) = keypair(&mut pk_buf, &mut sk_buf, &mut rng);
        let (ct, ss) = encapsulate(&pk, &mut ss_buf1, &mut rng);
        let ss2 = decapsulate(&ct, &sk, &mut ss_buf2);

        actual.pk = *pk.as_array();
        actual.sk = *sk.as_array();
        assert_eq!(ss.as_array(), ss2.as_array());
        actual.ss = *ss.as_array();
        actual.ct.copy_from_slice(ct.as_ref());

        //assert_eq!(expected, actual);
        assert_eq!(
            expected.seed, actual.seed,
            "seeds of testcase {} don't match",
            expected.count
        );
        assert_eq!(
            expected.pk, actual.pk,
            "public keys of testcase {} don't match",
            expected.count
        );
        assert_eq!(
            expected.sk, actual.sk,
            "secret keys of testcase {} don't match",
            expected.count
        );
        assert_eq!(
            expected.ct, actual.ct,
            "ciphertexts of testcase {} don't match",
            expected.count
        );
        assert_eq!(
            expected.ss, actual.ss,
            "shared secrets of testcase {} don't match",
            expected.count
        );
    }

    Ok(())
}

#[cfg(test)]
macro_rules! impl_parser_per_type {
    ($name:ident, $bitsize:expr, $t:ty) => {
        /// Parses a testdata file and returns a vector of $ty stored for the given `search_key`.
        /// The value is parsed in big-endian order.
        ///
        /// I started to write a zero-allocation parser, but it takes many lines of code.
        /// This design allocates, but can be comprehended much easier.
        fn $name(&self, search_key: &str) -> Vec<$t> {
            use std::convert::TryInto;
            use std::str;

            let content = match str::from_utf8(self.data) {
                Ok(v) => v,
                Err(e) => panic!("testdata.txt contains invalid UTF-8 data: {}", e),
            };

            for (lineno, line) in content.lines().enumerate() {
                let inner_line = line.trim();
                if inner_line.starts_with('#') {
                    continue;
                }
                let mut key = "";
                let mut value = "";
                for (f, field) in inner_line.split('=').enumerate() {
                    match f {
                        0 => key = field.trim(),
                        1 => value = field.trim(),
                        _ => {}
                    }
                }
                if key != search_key {
                    continue;
                }
                if value == "" {
                    panic!("empty value for key '{}' at line {}", search_key, lineno);
                }
                let bytes = hex::decode(value).expect("invalid hex data in value");
                let bytes_per_element = $bitsize / 8;
                let elements_count = bytes.len() / bytes_per_element;
                let mut elements = Vec::<$t>::with_capacity(elements_count);
                for idx in 0..elements_count {
                    let element = &bytes[bytes_per_element * idx..bytes_per_element * (idx + 1)];
                    elements.push(<$t>::from_be_bytes(
                        element.try_into().expect("invalid slice length"),
                    ));
                }
                return elements;
            }

            panic!("search_key '{}' not found in testdata.txt", search_key);
        }
    };
}

#[cfg(test)]
struct TestData {
    data: &'static [u8],
}

#[cfg(test)]
impl TestData {
    fn new() -> TestData {
        let bytes = include_bytes!("../data/testdata.txt");
        TestData { data: bytes }
    }

    impl_parser_per_type!(u8vec, 8, u8);
    impl_parser_per_type!(u16vec, 16, u16);
    impl_parser_per_type!(u32vec, 32, u32);
    impl_parser_per_type!(u64vec, 64, u64);
    //impl_parser_per_type!(i8vec, 8, i8);
    #[cfg(any(
        feature = "mceliece348864",
        feature = "mceliece6960119",
        feature = "mceliece8192128f"
    ))]
    impl_parser_per_type!(i16vec, 16, i16);
    //impl_parser_per_type!(i32vec, 32, i32);
    //impl_parser_per_type!(i64vec, 64, i64);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_katkem() {
        std::thread::Builder::new()
            .stack_size(10 * 1024 * 1024)
            .spawn(|| {
                let mut args = env::args();
                match args.len() {
                    3 => {
                        args.next().unwrap();
                        args.next().unwrap();
                        let rsp_file = args.next().unwrap();
                        verify(&rsp_file).unwrap();

                        println!("verification successful.");
                    }

                    5 => {
                        args.next().unwrap();
                        args.next().unwrap();

                        let req_file = args.next().unwrap();
                        let rsp_file = args.next().unwrap();

                        create_request_file(&req_file).unwrap();
                        println!("request file '{}' created.", &req_file);

                        create_response_file(&rsp_file).unwrap();
                        println!("request file '{}' created.", &rsp_file);
                    }

                    _ => {
                        eprintln!("usage: ./PQCgenKAT_kem <request:filepath> <response:filepath>");
                        eprintln!("  generate a request and response file\n");
                        eprintln!("usage: ./PQCgenKAT_kem <response:filepath>");
                        eprintln!("  verify the given response file\n");
                        panic!("wrong number of arguments");
                    }
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn testdata_sanity_check() {
        assert_eq!(
            TestData::new().u8vec("sanity_check"),
            [0x01, 0x23, 0x45, 0x67].to_vec()
        );
        assert_eq!(
            TestData::new().u16vec("sanity_check"),
            [0x0123, 0x4567].to_vec()
        );
        assert_eq!(
            TestData::new().u32vec("sanity_check"),
            [0x01234567].to_vec()
        );
    }
}
