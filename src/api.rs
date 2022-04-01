//! Global constants that are part of the API (i.e. array sizes)

#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
/// The number of bytes required to store the public key
pub const CRYPTO_PUBLICKEYBYTES: usize = 261120;
#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
/// The number of bytes required to store the secret key
pub const CRYPTO_SECRETKEYBYTES: usize = 6492;
#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
/// The number of bytes required to store the ciphertext resulting from the encryption
pub const CRYPTO_CIPHERTEXTBYTES: usize = 128;

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

#[cfg(feature = "mceliece8192128")]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "mceliece8192128";
#[cfg(feature = "mceliece8192128f")]
/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "mceliece8192128f";

/// The number of bytes required to store the shared secret negotiated between both parties
// this value is uniform
pub const CRYPTO_BYTES: usize = 32;
