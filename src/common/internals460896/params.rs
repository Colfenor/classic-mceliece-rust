pub use crate::common::gf13::{COND_BYTES, GFBITS, GFMASK};
pub const SYS_N: usize = 4608;
pub const SYS_T: usize = 96;
pub const IRR_BYTES: usize = SYS_T * 2;
pub const PK_NROWS: usize = SYS_T * GFBITS;
pub const PK_NCOLS: usize = SYS_N - PK_NROWS;
pub const PK_ROW_BYTES: usize = (PK_NCOLS + 7) / 8;
pub const SYND_BYTES: usize = (PK_NROWS + 7) / 8;

/// The number of bytes required to store the public key
pub const CRYPTO_PUBLICKEYBYTES: usize = 524160;
/// The number of bytes required to store the secret key
pub const CRYPTO_SECRETKEYBYTES: usize = 13608;
/// The number of bytes required to store the ciphertext resulting from the encryption
pub const CRYPTO_CIPHERTEXTBYTES: usize = 188;
/// The number of bytes required to store the shared secret negotiated between both parties
pub const CRYPTO_BYTES: usize = 32;
