/// The number of bytes required to store the public key
pub const CRYPTO_PUBLICKEYBYTES: usize = 261120;
/// The number of bytes required to store the secret key
pub const CRYPTO_SECRETKEYBYTES: usize = 6492;
/// The number of bytes required to store the ciphertext resulting from the encryption
pub const CRYPTO_CIPHERTEXTBYTES: usize = 128;
/// The number of bytes required to store the shared secret negotiated between both parties
pub const CRYPTO_BYTES: usize = 32;

/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "mceliece348864f";
