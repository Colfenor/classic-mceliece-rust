use std::error;

use crate::{
    params::{PK_NROWS, PK_ROW_BYTES, SYND_BYTES, SYS_N, SYS_T},
    randombytes::RNGState,
    util::load_gf,
};

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
fn gen_e(e: &mut [u8], rng: &mut impl RNGState) -> Result<(), Box<dyn error::Error>> {
    let mut ind = [0u16; SYS_T];
    let mut bytes = [0u8; SYS_T * 2];
    let mut val = [0u8; SYS_T];

    loop {
        rng.randombytes(&mut bytes)?;

        let mut i = 0;
        for chunk in bytes.chunks_mut((i + 1) * 2) {
            ind[i] = load_gf(chunk);
            i += 1;
            if i == SYS_T {
                break;
            }
        }

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

    Ok(())
}

/// Syndrome computation.
///
/// Computes syndrome `s` based on public key `pk` and error vector `e`.
fn syndrome(s: &mut [u8], pk: &[u8], e: &[u8]) {
    let mut row = [0u8; SYS_N / 8];

    let mut pk_segment = pk;

    for i in 0..SYND_BYTES {
        s[i] = 0;
    }

    for i in 0..PK_NROWS {
        for j in 0..SYS_N / 8 {
            row[j] = 0;
        }

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
pub fn encrypt(s: &mut [u8], pk: &[u8], e: &mut [u8], rng: &mut impl RNGState) -> Result<(), Box<dyn error::Error>> {
    gen_e(e, rng)?;
    syndrome(s, pk, e);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "mceliece8192128f", test))]
    use super::*;
    #[cfg(all(feature = "mceliece8192128f", test))]
    use crate::api::CRYPTO_CIPHERTEXTBYTES;
    #[cfg(all(feature = "mceliece8192128f", test))]
    use crate::api::CRYPTO_PUBLICKEYBYTES;
    #[cfg(all(feature = "mceliece8192128f", test))]
    use crate::randombytes::AesState;

    #[test]
    pub fn test_encrypt() -> Result<(), Box<dyn error::Error>> {
        let mut entropy_input = [
            6, 21, 80, 35, 77, 21, 140, 94, 201, 85, 149, 254, 4, 239, 122, 37, 118, 127, 46, 36,
            204, 43, 196, 121, 208, 157, 134, 220, 154, 188, 253, 231, 5, 106, 140, 38, 111, 158,
            249, 126, 208, 133, 65, 219, 210, 225, 255, 161,
        ];

        let mut rng_state = AesState::new();
        rng_state.randombytes_init(entropy_input);

        let mut second_seed = [0u8; 33];
        second_seed[0] = 64;

        rng_state.randombytes(&mut second_seed[1..])?;

        let mut two_e = [0u8; 1 + SYS_N / 8];
        two_e[0] = 2;

        let mut c = [0u8; CRYPTO_CIPHERTEXTBYTES];
        let mut pk = crate::TestData::new().u8vec("PK_INPUT");
        assert_eq!(pk.len(), CRYPTO_PUBLICKEYBYTES);

        let test_e = crate::TestData::new().u8vec("TEST_E");
        assert_eq!(test_e.len(), SYS_N / 8);

        let compare_s = crate::TestData::new().u8vec("COMPARE_S");
        assert_eq!(compare_s.len(), CRYPTO_CIPHERTEXTBYTES);

        encrypt(&mut c, &mut pk, &mut two_e[1..], &mut rng_state)?;

        assert_eq!(compare_s, c);

        Ok(())
    }
}
