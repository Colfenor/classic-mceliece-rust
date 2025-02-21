//! Encryption function to compute error vector and syndrome to get ciphertext

use crate::{
    api::CRYPTO_CIPHERTEXTBYTES,
    macros::sub,
    params::{PK_NROWS, PK_ROW_BYTES, SYND_BYTES, SYS_N, SYS_T},
    util::load_gf,
};
use rand::{CryptoRng, RngCore};

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
fn gen_e<R: CryptoRng + RngCore>(e: &mut [u8; SYS_N / 8], rng: &mut R) {
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
fn gen_e<R: CryptoRng + RngCore>(e: &mut [u8], rng: &mut R) {
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
#[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
fn syndrome(
    s: &mut [u8; (PK_NROWS + 7) / 8],
    pk: &[u8; PK_NROWS * PK_ROW_BYTES],
    e: &[u8; SYS_N / 8],
) {
    let mut row = [0u8; SYS_N / 8];

    let mut pk_segment = &pk[..];
    let tail = PK_NROWS % 8;

    s[0..SYND_BYTES].fill(0);

    for i in 0..PK_NROWS {
        row[0..SYS_N / 8].fill(0);

        for j in 0..PK_ROW_BYTES {
            row[SYS_N / 8 - PK_ROW_BYTES + j] = pk_segment[j];
        }

        for j in ((SYS_N / 8 - PK_ROW_BYTES)..SYS_N / 8).rev() {
            row[j] = (row[j] << tail) | (row[j - 1] >> (8 - tail));
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

        pk_segment = &pk_segment[PK_ROW_BYTES..];
    }
}

/// Syndrome computation.
///
/// Computes syndrome `s` based on public key `pk` and error vector `e`.
#[cfg(not(any(feature = "mceliece6960119", feature = "mceliece6960119f")))]
fn syndrome(
    s: &mut [u8; PK_NROWS.div_ceil(8)],
    pk: &[u8; PK_NROWS * PK_ROW_BYTES],
    e: &[u8; SYS_N / 8],
) {
    let mut row = [0u8; SYS_N / 8];

    let mut pk_segment = &pk[..];

    s[0..SYND_BYTES].fill(0);

    for i in 0..PK_NROWS {
        row[0..SYS_N / 8].fill(0);

        for j in 0..PK_ROW_BYTES {
            row[SYS_N / 8 - PK_ROW_BYTES + j] = pk_segment[j];
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

        pk_segment = &pk_segment[PK_ROW_BYTES..];
    }
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
    #[cfg(feature = "mceliece8192128f")]
    use super::*;
    #[cfg(feature = "mceliece8192128f")]
    use crate::api::CRYPTO_CIPHERTEXTBYTES;
    #[cfg(feature = "mceliece8192128f")]
    use crate::api::CRYPTO_PUBLICKEYBYTES;
    #[cfg(feature = "mceliece8192128f")]
    use crate::nist_aes_rng::AesState;
    #[cfg(feature = "mceliece8192128f")]
    use crate::test_utils::TestData;

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
}
