//! Streaming public-key reader support.
//!
//! Public keys are consumed incrementally from a caller-supplied reader. The
//! reader must supply exactly `CRYPTO_PUBLICKEYBYTES` bytes; `finish` enforces
//! that no trailing data remains. For padding-sensitive variants
//! (`mceliece6960119`/`mceliece6960119f`), nonzero padding bits trigger an
//! explicit error. Any reader error causes encapsulation outputs to be zeroed.

use crate::{
    api::{CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES},
    encrypt::gen_e,
    encrypt::syndrome_core,
    encrypt::RowReader,
    macros::sub,
    operations::derive_ss_from_e_and_c,
    params::{PK_NROWS, SYND_BYTES, SYS_N},
    Ciphertext, KeyBufferMut, SharedSecret,
};
use rand::{CryptoRng, RngCore};

/// A byte source for a serialized public key.
///
/// Implementations should supply exactly `CRYPTO_PUBLICKEYBYTES` bytes in
/// row-major order (PK_NROWS rows of PK_ROW_BYTES bytes).
pub trait PublicKeyReader {
    type Error;

    /// Fill `buf` with the next public-key bytes.
    ///
    /// Return an error on short reads or I/O failure.
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;

    /// Called after the public key has been read to enforce exact length.
    ///
    /// Implementations should return an error if trailing bytes remain.
    fn finish(&mut self) -> Result<(), Self::Error>;

    /// Called when padding bits are nonzero for padding-sensitive variants.
    ///
    /// Implementations should return an error describing invalid padding.
    fn invalid_padding(&self) -> Self::Error;
}

impl<P: PublicKeyReader> RowReader for P {
    type Error = P::Error;

    fn read_row(&mut self, row: &mut [u8]) -> Result<(), Self::Error> {
        self.read_exact(row)
    }

    fn finish(&mut self) -> Result<(), Self::Error> {
        PublicKeyReader::finish(self)
    }

    fn invalid_padding(&self) -> Self::Error {
        PublicKeyReader::invalid_padding(self)
    }
}

/// Syndrome computation using a streaming public key reader.
fn syndrome_from_reader<P: PublicKeyReader>(
    s: &mut [u8; PK_NROWS.div_ceil(8)],
    pk_reader: &mut P,
    e: &[u8; SYS_N / 8],
) -> Result<(), P::Error> {
    const HAS_TAIL: bool = PK_NROWS % 8 != 0;
    const CHECK_PADDING: bool = cfg!(any(
        feature = "mceliece6960119",
        feature = "mceliece6960119f"
    ));

    syndrome_core::<_, { HAS_TAIL }, { CHECK_PADDING }>(s, e, pk_reader)
}

/// Encryption routine using a streaming public key reader.
///
/// Returns an error if the reader fails, has trailing bytes, or if padding
/// bits are nonzero for padding-sensitive variants.
pub(crate) fn encrypt_from_reader<R, P>(
    s: &mut [u8; CRYPTO_CIPHERTEXTBYTES],
    pk_reader: &mut P,
    e: &mut [u8; SYS_N / 8],
    rng: &mut R,
) -> Result<(), P::Error>
where
    R: CryptoRng + RngCore,
    P: PublicKeyReader,
{
    gen_e(e, rng);
    syndrome_from_reader(sub!(mut s, 0, PK_NROWS.div_ceil(8)), pk_reader, e)
}

/// KEM Encapsulation using a streaming public key reader.
///
/// On error, `c` and `key` are zeroed before the error is returned.
/// Errors include short reads, trailing bytes, or invalid padding for
/// padding-sensitive variants.
pub(crate) fn crypto_kem_enc_from_reader<R, P>(
    c: &mut [u8; CRYPTO_CIPHERTEXTBYTES],
    key: &mut [u8; CRYPTO_BYTES],
    pk_reader: &mut P,
    rng: &mut R,
) -> Result<(), P::Error>
where
    R: CryptoRng + RngCore,
    P: PublicKeyReader,
{
    let mut e = [0u8; SYS_N / 8];

    if let Err(err) = encrypt_from_reader(c, pk_reader, sub!(mut e, 0, SYS_N / 8), rng) {
        c.fill(0);
        key.fill(0);
        return Err(err);
    }

    derive_ss_from_e_and_c(key, &e, sub!(c, 0, SYND_BYTES));
    Ok(())
}

/// KEM Encapsulation using a streaming public key reader.
///
/// This is useful on memory-constrained systems where the public key cannot
/// be kept fully in RAM.
///
/// Returns an error if the reader is short, has trailing bytes, or if
/// padding bits are nonzero for padding-sensitive variants.
pub fn encapsulate_from_reader<'shared_secret, R, P>(
    public_key_reader: &mut P,
    shared_secret_buf: &'shared_secret mut [u8; CRYPTO_BYTES],
    rng: &mut R,
) -> Result<(Ciphertext, SharedSecret<'shared_secret>), P::Error>
where
    R: CryptoRng + RngCore,
    P: PublicKeyReader,
{
    let mut shared_secret_buf = KeyBufferMut::Borrowed(shared_secret_buf);
    let mut ciphertext_buf = [0u8; CRYPTO_CIPHERTEXTBYTES];

    crypto_kem_enc_from_reader(
        &mut ciphertext_buf,
        shared_secret_buf.as_mut(),
        public_key_reader,
        rng,
    )?;

    Ok((Ciphertext(ciphertext_buf), SharedSecret(shared_secret_buf)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{generate_public_key_bytes, SliceReader};
    #[cfg(feature = "embedded-workspace")]
    use crate::DecapsulationWorkspace;
    use crate::{
        decapsulate, keypair, CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES,
        CRYPTO_SECRETKEYBYTES,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use std::convert::TryInto;

    #[test]
    fn test_encapsulate_from_reader_roundtrip() {
        let mut pk_storage = vec![0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk_storage = vec![0u8; CRYPTO_SECRETKEYBYTES];

        let pk_array: &mut [u8; CRYPTO_PUBLICKEYBYTES] =
            pk_storage.as_mut_slice().try_into().unwrap();
        let sk_array: &mut [u8; CRYPTO_SECRETKEYBYTES] =
            sk_storage.as_mut_slice().try_into().unwrap();

        let mut keygen_rng = StdRng::from_seed([0x3C; 32]);
        let (public_key, secret_key) = keypair(pk_array, sk_array, &mut keygen_rng);
        let pk_bytes = public_key.as_array().to_vec();

        let mut reader = SliceReader {
            data: pk_bytes.as_slice(),
            pos: 0,
        };
        let mut ss1_buf = [0u8; CRYPTO_BYTES];
        let mut enc_rng = StdRng::from_seed([0x6A; 32]);
        let (ciphertext, ss1) =
            encapsulate_from_reader(&mut reader, &mut ss1_buf, &mut enc_rng).unwrap();

        let mut ss2_buf = [0u8; CRYPTO_BYTES];
        #[cfg(feature = "embedded-workspace")]
        let ss2 = {
            let mut workspace = DecapsulationWorkspace::new();
            decapsulate(&ciphertext, &secret_key, &mut ss2_buf, &mut workspace)
        };
        #[cfg(not(feature = "embedded-workspace"))]
        let ss2 = decapsulate(&ciphertext, &secret_key, &mut ss2_buf);

        assert_eq!(reader.pos, CRYPTO_PUBLICKEYBYTES);
        assert_eq!(ss1.as_array(), ss2.as_array());
    }

    #[test]
    fn test_encapsulate_from_reader_rejects_trailing_bytes() {
        let mut pk_bytes = generate_public_key_bytes([0x3C; 32]);
        pk_bytes.push(0x00);

        let mut reader = SliceReader {
            data: pk_bytes.as_slice(),
            pos: 0,
        };
        let mut ss_buf = [0u8; CRYPTO_BYTES];
        let mut rng = StdRng::from_seed([0x6A; 32]);

        assert!(encapsulate_from_reader(&mut reader, &mut ss_buf, &mut rng).is_err());
    }

    #[test]
    fn test_encapsulate_from_reader_rejects_short_read() {
        let mut pk_bytes = generate_public_key_bytes([0x3C; 32]);
        pk_bytes.pop();

        let mut reader = SliceReader {
            data: pk_bytes.as_slice(),
            pos: 0,
        };
        let mut ss_buf = [0u8; CRYPTO_BYTES];
        let mut rng = StdRng::from_seed([0x6A; 32]);

        assert!(encapsulate_from_reader(&mut reader, &mut ss_buf, &mut rng).is_err());
    }

    #[test]
    #[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
    fn test_encapsulate_from_reader_rejects_invalid_padding() {
        let mut pk_bytes = generate_public_key_bytes([0x3C; 32]);
        let padding_mask = 0xFFu8 << (crate::params::PK_NCOLS % 8);
        pk_bytes[crate::params::PK_ROW_BYTES - 1] |= padding_mask;

        let mut reader = SliceReader {
            data: pk_bytes.as_slice(),
            pos: 0,
        };
        let mut ss_buf = [0u8; CRYPTO_BYTES];
        let mut rng = StdRng::from_seed([0x6A; 32]);

        assert!(encapsulate_from_reader(&mut reader, &mut ss_buf, &mut rng).is_err());
    }

    #[test]
    fn test_crypto_kem_enc_from_reader_zeroes_on_short_read() {
        let mut pk_bytes = generate_public_key_bytes([0x3C; 32]);
        pk_bytes.pop();

        let mut reader = SliceReader {
            data: pk_bytes.as_slice(),
            pos: 0,
        };
        let mut c = [0u8; CRYPTO_CIPHERTEXTBYTES];
        let mut key = [0u8; CRYPTO_BYTES];
        let mut rng = StdRng::from_seed([0x6A; 32]);

        assert!(crypto_kem_enc_from_reader(&mut c, &mut key, &mut reader, &mut rng).is_err());
        assert!(c.iter().all(|&byte| byte == 0));
        assert!(key.iter().all(|&byte| byte == 0));
    }

    #[test]
    fn test_crypto_kem_enc_from_reader_zeroes_on_trailing_bytes() {
        let mut pk_bytes = generate_public_key_bytes([0x3C; 32]);
        pk_bytes.push(0x00);

        let mut reader = SliceReader {
            data: pk_bytes.as_slice(),
            pos: 0,
        };
        let mut c = [0u8; CRYPTO_CIPHERTEXTBYTES];
        let mut key = [0u8; CRYPTO_BYTES];
        let mut rng = StdRng::from_seed([0x6A; 32]);

        assert!(crypto_kem_enc_from_reader(&mut c, &mut key, &mut reader, &mut rng).is_err());
        assert!(c.iter().all(|&byte| byte == 0));
        assert!(key.iter().all(|&byte| byte == 0));
    }

    #[test]
    #[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
    fn test_crypto_kem_enc_from_reader_zeroes_on_invalid_padding() {
        let mut pk_bytes = generate_public_key_bytes([0x3C; 32]);
        let padding_mask = 0xFFu8 << (crate::params::PK_NCOLS % 8);
        pk_bytes[crate::params::PK_ROW_BYTES - 1] |= padding_mask;

        let mut reader = SliceReader {
            data: pk_bytes.as_slice(),
            pos: 0,
        };
        let mut c = [0u8; CRYPTO_CIPHERTEXTBYTES];
        let mut key = [0u8; CRYPTO_BYTES];
        let mut rng = StdRng::from_seed([0x6A; 32]);

        assert!(crypto_kem_enc_from_reader(&mut c, &mut key, &mut reader, &mut rng).is_err());
        assert!(c.iter().all(|&byte| byte == 0));
        assert!(key.iter().all(|&byte| byte == 0));
    }
}
