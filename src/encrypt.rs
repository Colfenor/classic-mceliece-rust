//! Encryption function to compute error vector and syndrome to get ciphertext

use crate::{
    api::CRYPTO_CIPHERTEXTBYTES,
    macros::sub,
    params::{PK_NROWS, PK_ROW_BYTES, SYND_BYTES, SYS_N, SYS_T},
    util::load_gf,
};
use rand::{CryptoRng, RngCore};

pub(crate) trait RowReader {
    type Error;

    fn read_row(&mut self, row: &mut [u8]) -> Result<(), Self::Error>;
    fn finish(&mut self) -> Result<(), Self::Error>;
    fn invalid_padding(&self) -> Self::Error;
}

/// Takes two 16-bit integers and determines whether they are equal (u8::MAX) or different (0)
fn same_mask_u8(x: u16, y: u16) -> u8 {
    let mut mask = (x ^ y) as u32;
    mask = mask.wrapping_sub(1);
    mask = mask.wrapping_shr(31);
    mask = 0u32.wrapping_sub(mask);

    (mask & 0xFF) as u8 // ∈ {0, u8::MAX}
}

/// Generation of `e`, an error vector of weight `t`.
/// Does not take any input arguments.
/// If generation of pseudo-random numbers fails, an error is returned.
#[cfg(not(any(feature = "mceliece8192128", feature = "mceliece8192128f")))]
pub(crate) fn gen_e<R: CryptoRng + RngCore>(e: &mut [u8; SYS_N / 8], rng: &mut R) {
    let mut ind = [0u16; SYS_T];
    let mut val = [0u8; SYS_T];

    loop {
        let mut bytes = [0u8; SYS_T * 4];
        rng.fill_bytes(&mut bytes);

        let mut nums = [0u16; SYS_T * 2];
        for (i, chunk) in bytes.chunks(2).enumerate() {
            nums[i] = load_gf(sub!(chunk, 0, 2));
        }

        // moving and counting indices in the correct range

        let mut count = 0;
        for itr_num in nums.iter() {
            if count >= SYS_T {
                break;
            }
            if *itr_num < SYS_N as u16 {
                ind[count] = *itr_num;
                count += 1;
            }
        }

        if count < SYS_T {
            continue;
        }

        // check for repetition

        let mut eq = 0;

        for i in 1..SYS_T {
            for j in 0..i {
                if ind[i] == ind[j] {
                    eq = 1;
                }
            }
        }

        if eq == 0 {
            break;
        }
    }

    for j in 0..SYS_T {
        val[j] = 1 << (ind[j] & 7);
    }

    for (i, itr_e) in e.iter_mut().enumerate() {
        *itr_e = 0;

        for j in 0..SYS_T {
            let mask: u8 = same_mask_u8(i as u16, ind[j] >> 3);

            *itr_e |= val[j] & mask;
        }
    }
}

/// Generation of `e`, an error vector of weight `t`.
/// Does not take any input arguments.
/// If generation of pseudo-random numbers fails, an error is returned.
#[cfg(any(feature = "mceliece8192128", feature = "mceliece8192128f"))]
pub(crate) fn gen_e<R: CryptoRng + RngCore>(e: &mut [u8], rng: &mut R) {
    let mut ind = [0u16; SYS_T];
    let mut bytes = [0u8; SYS_T * 2];
    let mut val = [0u8; SYS_T];

    loop {
        rng.fill_bytes(&mut bytes);

        for (i, chunk) in bytes.chunks(2).enumerate() {
            ind[i] = load_gf(sub!(chunk, 0, 2));
        }

        // check for repetition

        let mut eq = 0;

        for i in 1..SYS_T {
            for j in 0..i {
                if ind[i] == ind[j] {
                    eq = 1;
                }
            }
        }

        if eq == 0 {
            break;
        }
    }

    for j in 0..SYS_T {
        val[j] = 1 << (ind[j] & 7);
    }

    for i in 0..SYS_N / 8 {
        e[i] = 0;

        for j in 0..SYS_T {
            let mask: u8 = same_mask_u8(i as u16, ind[j] >> 3);

            e[i] |= val[j] & mask;
        }
    }
}

/// Syndrome computation.
///
/// Computes syndrome `s` based on public key `pk` and error vector `e`.
///
/// Note: `RowReader` is a generic trait (no dynamic dispatch). Release asm
/// checks for the examples showed no out-of-line symbols/calls for these
/// methods; they inline away.
pub(crate) fn syndrome_core<R, const HAS_TAIL: bool, const CHECK_PADDING: bool>(
    s: &mut [u8; PK_NROWS.div_ceil(8)],
    e: &[u8; SYS_N / 8],
    reader: &mut R,
) -> Result<(), R::Error>
where
    R: RowReader,
{
    let mut row = [0u8; SYS_N / 8];
    let tail = PK_NROWS % 8;
    let mut padding_or = 0u8;

    s[0..SYND_BYTES].fill(0);

    for i in 0..PK_NROWS {
        row.fill(0);

        let row_bytes = &mut row[SYS_N / 8 - PK_ROW_BYTES..];
        reader.read_row(row_bytes)?;

        if CHECK_PADDING {
            padding_or |= row_bytes[PK_ROW_BYTES - 1];
        }

        if HAS_TAIL {
            for j in ((SYS_N / 8 - PK_ROW_BYTES)..SYS_N / 8).rev() {
                row[j] = (row[j] << tail) | (row[j - 1] >> (8 - tail));
            }
        }

        row[i / 8] |= 1 << (i % 8);

        let mut b = 0u8;
        for j in 0..SYS_N / 8 {
            b ^= row[j] & e[j];
        }

        b ^= b >> 4;
        b ^= b >> 2;
        b ^= b >> 1;
        b &= 1;

        s[i / 8] |= b << (i % 8);
    }

    reader.finish()?;

    if CHECK_PADDING {
        if (padding_or >> (crate::params::PK_NCOLS % 8)) != 0 {
            return Err(reader.invalid_padding());
        }
    }

    Ok(())
}

/// Syndrome computation.
///
/// Computes syndrome `s` based on public key `pk` and error vector `e`.
fn syndrome(
    s: &mut [u8; PK_NROWS.div_ceil(8)],
    pk: &[u8; PK_NROWS * PK_ROW_BYTES],
    e: &[u8; SYS_N / 8],
) {
    const HAS_TAIL: bool = PK_NROWS % 8 != 0;

    struct PkSliceRows<'a> {
        pk: &'a [u8; PK_NROWS * PK_ROW_BYTES],
        offset: usize,
    }

    impl<'a> RowReader for PkSliceRows<'a> {
        type Error = ();

        fn read_row(&mut self, row: &mut [u8]) -> Result<(), Self::Error> {
            let end = self.offset + PK_ROW_BYTES;
            row.copy_from_slice(&self.pk[self.offset..end]);
            self.offset = end;
            Ok(())
        }

        fn finish(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn invalid_padding(&self) -> Self::Error {
            unreachable!()
        }
    }

    let mut reader = PkSliceRows { pk, offset: 0 };
    let _ = syndrome_core::<_, { HAS_TAIL }, false>(s, e, &mut reader);
}

/// Encryption routine.
/// Takes a public key `pk` to compute error vector `e` and syndrome `s`.
pub(crate) fn encrypt<R: CryptoRng + RngCore>(
    s: &mut [u8; CRYPTO_CIPHERTEXTBYTES],
    pk: &[u8; PK_NROWS * PK_ROW_BYTES],
    e: &mut [u8; SYS_N / 8],
    rng: &mut R,
) {
    gen_e(e, rng);
    syndrome(sub!(mut s, 0, PK_NROWS.div_ceil(8)), pk, e);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::api::{CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES};
    #[cfg(feature = "mceliece8192128f")]
    use crate::nist_aes_rng::AesState;
    #[cfg(feature = "mceliece8192128f")]
    use crate::test_utils::TestData;
    use crate::test_utils::{generate_public_key_bytes, SliceReader};

    #[test]
    fn test_encrypt_from_reader_matches_encrypt() {
        let pk = generate_public_key_bytes([0x42; 32]);
        let mut c_direct = [0u8; CRYPTO_CIPHERTEXTBYTES];
        let mut c_reader = [0u8; CRYPTO_CIPHERTEXTBYTES];
        let mut e_direct = [0u8; SYS_N / 8];
        let mut e_reader = [0u8; SYS_N / 8];

        let mut rng_direct = StdRng::from_seed([0x24; 32]);
        let mut rng_reader = StdRng::from_seed([0x24; 32]);

        encrypt(
            &mut c_direct,
            sub!(pk, 0, CRYPTO_PUBLICKEYBYTES),
            &mut e_direct,
            &mut rng_direct,
        );

        let mut reader = SliceReader { data: &pk, pos: 0 };
        crate::streaming::encrypt_from_reader(
            &mut c_reader,
            &mut reader,
            &mut e_reader,
            &mut rng_reader,
        )
        .unwrap();

        assert_eq!(reader.pos, CRYPTO_PUBLICKEYBYTES);
        assert_eq!(e_direct, e_reader);
        assert_eq!(c_direct, c_reader);
    }

    #[test]
    #[cfg(feature = "mceliece8192128f")]
    fn test_encrypt() {
        let entropy_input = [
            6, 21, 80, 35, 77, 21, 140, 94, 201, 85, 149, 254, 4, 239, 122, 37, 118, 127, 46, 36,
            204, 43, 196, 121, 208, 157, 134, 220, 154, 188, 253, 231, 5, 106, 140, 38, 111, 158,
            249, 126, 208, 133, 65, 219, 210, 225, 255, 161,
        ];

        let mut rng_state = AesState::new();
        rng_state.randombytes_init(entropy_input);

        let mut second_seed = [0u8; 33];
        second_seed[0] = 64;

        rng_state.fill_bytes(&mut second_seed[1..]);

        let mut e = [0u8; SYS_N / 8];

        let mut c = [0u8; CRYPTO_CIPHERTEXTBYTES];
        let mut pk = TestData::new().u8vec("mceliece8192128f_pk1");

        let compare_ct = TestData::new().u8vec("mceliece8192128f_encrypt_ct");
        assert_eq!(compare_ct.len(), CRYPTO_CIPHERTEXTBYTES);

        encrypt(
            &mut c,
            sub!(mut pk, 0, CRYPTO_PUBLICKEYBYTES),
            sub!(mut e, 0, SYS_N / 8),
            &mut rng_state,
        );

        assert_eq!(compare_ct, c);
    }

    #[test]
    #[cfg(feature = "mceliece8192128f")]
    fn test_encrypt_from_reader() {
        let entropy_input = [
            6, 21, 80, 35, 77, 21, 140, 94, 201, 85, 149, 254, 4, 239, 122, 37, 118, 127, 46, 36,
            204, 43, 196, 121, 208, 157, 134, 220, 154, 188, 253, 231, 5, 106, 140, 38, 111, 158,
            249, 126, 208, 133, 65, 219, 210, 225, 255, 161,
        ];

        let mut rng_state = AesState::new();
        rng_state.randombytes_init(entropy_input);

        let mut second_seed = [0u8; 33];
        second_seed[0] = 64;

        rng_state.fill_bytes(&mut second_seed[1..]);

        let mut e = [0u8; SYS_N / 8];

        let mut c = [0u8; CRYPTO_CIPHERTEXTBYTES];
        let pk = TestData::new().u8vec("mceliece8192128f_pk1");

        let compare_ct = TestData::new().u8vec("mceliece8192128f_encrypt_ct");
        assert_eq!(compare_ct.len(), CRYPTO_CIPHERTEXTBYTES);

        let mut reader = SliceReader { data: &pk, pos: 0 };
        crate::streaming::encrypt_from_reader(
            &mut c,
            &mut reader,
            sub!(mut e, 0, SYS_N / 8),
            &mut rng_state,
        )
        .unwrap();

        assert_eq!(reader.pos, CRYPTO_PUBLICKEYBYTES);
        assert_eq!(compare_ct, c);
    }
}
