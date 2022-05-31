//! This file is for Beneš network related functions
//!
//! For the implementation strategy, see
//! “McBits Revisited” by Tung Chou (2017)
//! <https://eprint.iacr.org/2017/793.pdf>

use crate::gf::Gf;
use crate::macros::sub;
use crate::params::SYS_N;
use crate::params::{COND_BYTES, GFBITS};
use crate::transpose;
use crate::util;

/// Layers of the Beneš network. The required size of `data` and `bits` depends on the value `lgs`.
/// NOTE const expressions are not sophisticated enough in rust yet to represent this relationship.
///
/// | lgs | data.len() | bits.len() |
/// | ------ | ------ | ------ |
/// | 8 | 512 | 256 |
/// | 7 | 256 | 128 |
/// | 6 | 128 | 64 |
/// | 5 | 64 | 32 |
/// | 4 | 64 | 32 |
#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
fn layer(data: &mut [u64], bits: &[u64], lgs: usize) {
    let mut index = 0;

    let s = 1 << lgs;

    let mut i = 0usize;
    while i < 64 {
        for j in i..(i + s) {
            let mut d = data[j + 0] ^ data[j + s];
            d &= bits[index];
            index += 1;

            data[j + 0] ^= d;
            data[j + s] ^= d;
        }
        i += s * 2;
    }
}

/// Inner layers of the Beneš network. The required size of `data` and `bits` depends on the value `lgs`.
/// `data[0]`, `data[1]` and `bits` must have the same length; namely `2^(lgs + 1)` with `lgs ≥ 5`.
#[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
fn layer_in<const L: usize>(data: &mut [[u64; L]; 2], bits: &[u64; L], lgs: usize) {
    let mut d: u64;
    let mut index = 0;

    let s = 1 << lgs;

    let mut i = 0usize;
    while i < 64 {
        for j in i..(i + s) {
            d = data[0][j + 0] ^ data[0][j + s];
            d &= bits[index];
            index += 1;

            data[0][j + 0] ^= d;
            data[0][j + s] ^= d;

            d = data[1][j + 0] ^ data[1][j + s];
            d &= bits[index];
            index += 1;

            data[1][j + 0] ^= d;
            data[1][j + s] ^= d;
        }
        i += s * 2;
    }
}

/// Exterior layers of the Beneš network. The length of `bits` depends on the value of `lgs`.
/// NOTE const expressions are not sophisticated enough in rust yet to represent this relationship.
///
/// | lgs | data[0].len() == data[1].len() | bits.len() |
/// | ------ | ------ | ------ |
/// | 8 | 512 | 256 |
/// | 7 | 256 | 128 |
/// | 6 | 128 | 64 |
/// | 5 | 128 | 64 |
/// | 4 | 128 | 64 |
///
/// Also recognize that his implementation is quite different from the C implementation.
/// However, it does make sense. Whereas the C implementation uses pointer arithmetic to access
/// the entire array `data`, this implementation always considers `data` as two-dimensional array.
/// The C implementation uses 128 as upper bound (because the array contains 128 elements),
/// but this implementation has 64 elements per subarray and needs case distinctions at different places.
#[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
fn layer_ex(data: &mut [[u64; 64]; 2], bits: &[u64], lgs: usize) {
    let mut data0_idx = 0;
    let mut data1_idx = 32;

    let s = 1 << lgs;
    if s == 64 {
        // in this case where `s` has the highest possible value,
        // we need to access both subarrays in one expression.
        for j in 0..64 {
            let mut d = data[0][j + 0] ^ data[1][j];
            d &= bits[data0_idx];
            data0_idx += 1;

            data[0][j + 0] ^= d;
            data[1][j] ^= d;
        }
    } else {
        // in this case, we can run computations in both subarrays consecutively
        // within one iteration of loop over `j`
        let mut i: usize = 0;
        while i < 64 {
            for j in i..(i + s) {
                // data[0] computations
                let mut d = data[0][j + 0] ^ data[0][j + s];
                d &= bits[data0_idx];
                data0_idx += 1;

                data[0][j + 0] ^= d;
                data[0][j + s] ^= d;

                // data[1] computations
                d = data[1][j + 0] ^ data[1][j + s];
                d &= bits[data1_idx];
                data1_idx += 1;

                data[1][j + 0] ^= d;
                data[1][j + s] ^= d;
            }
            i += s * 2;
        }
    }
}

/// Apply Beneš network in-place to array `r` based on configuration `bits` and `rev`.
/// Here, `r` is a sequence of bits to be permuted.
/// `bits` defines the condition bits configuring the Beneš network and
/// `rev` toggles between normal application (0) or its inverse (!0).
#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
fn apply_benes(r: &mut [u8; 512], bits: &[u8; COND_BYTES], rev: usize) {
    let mut bs = [0u64; 64];
    let mut cond = [0u64; 64];

    if rev == 0 {
        for i in 0..64 {
            bs[i] = util::load8(sub!(r, i * 8, 8));
        }

        transpose::transpose_64x64_inplace(&mut bs);

        for low in 0..6 {
            for i in 0..64 {
                cond[i] = util::load4(sub!(bits, low * 256 + i * 4, 4)) as u64;
            }
            transpose::transpose_64x64_inplace(&mut cond);
            layer(&mut bs, &cond, low);
        }

        transpose::transpose_64x64_inplace(&mut bs);

        for low in 0..6 {
            for i in 0..32 {
                cond[i] = util::load8(sub!(bits, (low + 6) * 256 + i * 8, 8));
            }
            layer(&mut bs, &cond, low);
        }
        for low in (0..5).rev() {
            for i in 0..32 {
                cond[i] = util::load8(sub!(bits, (4 - low + 6 + 6) * 256 + i * 8, 8));
            }
            layer(&mut bs, &cond, low);
        }

        transpose::transpose_64x64_inplace(&mut bs);

        for low in (0..6).rev() {
            for i in 0..64 {
                cond[i] = util::load4(sub!(bits, (5 - low + 6 + 6 + 5) * 256 + i * 4, 4)) as u64;
            }
            transpose::transpose_64x64_inplace(&mut cond);
            layer(&mut bs, &cond, low);
        }

        transpose::transpose_64x64_inplace(&mut bs);

        for i in 0..64 {
            util::store8(sub!(mut r, i * 8, 8), bs[i]);
        }
    } else {
        for i in 0..64 {
            bs[i] = util::load8(sub!(r, i * 8, 8));
        }

        transpose::transpose_64x64_inplace(&mut bs);

        for low in 0..6 {
            for i in 0..64 {
                cond[i] =
                    util::load4(sub!(bits, (2 * GFBITS - 2) * 256 - low * 256 + i * 4, 4)) as u64;
            }
            transpose::transpose_64x64_inplace(&mut cond);
            layer(&mut bs, &cond, low);
        }

        transpose::transpose_64x64_inplace(&mut bs);

        for low in 0..6 {
            for i in 0..32 {
                cond[i] = util::load8(sub!(
                    bits,
                    (2 * GFBITS - 2 - 6) * 256 - low * 256 + i * 8,
                    8
                ));
            }
            layer(&mut bs, &cond, low);
        }
        for low in (0..5).rev() {
            for i in 0..32 {
                cond[i] = util::load8(sub!(
                    bits,
                    (2 * GFBITS - 2 - 6 - 6) * 256 - (4 - low) * 256 + i * 8,
                    8
                ));
                layer(&mut bs, &cond, low);
            }
        }

        transpose::transpose_64x64_inplace(&mut bs);

        for low in (0..6).rev() {
            for i in 0..64 {
                cond[i] = util::load4(sub!(
                    bits,
                    (2 * GFBITS - 2 - 6 - 6 - 5) * 256 - (5 - low) * 256 + i * 4,
                    4
                )) as u64;
            }
            transpose::transpose_64x64_inplace(&mut cond);
            layer(&mut bs, &cond, low);
        }

        transpose::transpose_64x64_inplace(&mut bs);

        for i in 0..64 {
            util::store8(sub!(mut r, i * 8, 8), bs[i]);
        }
    }
}

/// Apply Beneš network in-place to array `r` based on configuration `bits` and `rev`.
/// Here, `r` is a sequence of bits to be permuted.
/// `bits` defines the condition bits configuring the Beneš network and
/// `rev` toggles between normal application (0) or its inverse (!0).
#[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
fn apply_benes(r: &mut [u8; 1024], bits: &[u8; COND_BYTES], rev: usize) {
    let mut r_int_v = [[0u64; 64]; 2];
    let mut r_int_h = [[0u64; 64]; 2];
    let mut b_int_v = [0u64; 64];
    let mut b_int_h = [0u64; 64];

    let mut calc_index = if rev == 0 { 0 } else { 12288 };

    for (i, chunk) in r.chunks(16).enumerate() {
        r_int_v[0][i] = util::load8(sub!(chunk, 0, 8));
        r_int_v[1][i] = util::load8(sub!(chunk, 8, 8));
    }

    transpose::transpose(&mut r_int_h[0], r_int_v[0]);
    transpose::transpose(&mut r_int_h[1], r_int_v[1]);

    for iter in 0..=6 {
        for (i, chunk) in bits[calc_index..(calc_index + 512)].chunks(8).enumerate() {
            b_int_v[i] = util::load8(sub!(chunk, 0, 8));
        }

        calc_index = if rev == 0 {
            calc_index + 512
        } else {
            calc_index - 512
        };

        transpose::transpose(&mut b_int_h, b_int_v);

        layer_ex(&mut r_int_h, &mut b_int_h, iter);
    }

    transpose::transpose(&mut r_int_v[0], r_int_h[0]);
    transpose::transpose(&mut r_int_v[1], r_int_h[1]);

    for iter in 0..=5 {
        for (i, chunk) in bits[calc_index..(calc_index + 512)].chunks(8).enumerate() {
            b_int_v[i] = util::load8(sub!(chunk, 0, 8));
        }

        calc_index = if rev == 0 {
            calc_index + 512
        } else {
            calc_index - 512
        };

        layer_in(&mut r_int_v, &mut b_int_v, iter);
    }

    for iter in (0..=4).rev() {
        for (i, chunk) in bits[calc_index..(calc_index + 512)].chunks(8).enumerate() {
            b_int_v[i] = util::load8(sub!(chunk, 0, 8));
        }
        calc_index = if rev == 0 {
            calc_index + 512
        } else {
            calc_index - 512
        };

        layer_in(&mut r_int_v, &mut b_int_v, iter);
    }

    transpose::transpose(&mut r_int_h[0], r_int_v[0]);
    transpose::transpose(&mut r_int_h[1], r_int_v[1]);

    for iter in (0..=6).rev() {
        for (i, chunk) in bits[calc_index..(calc_index + 512)].chunks(8).enumerate() {
            b_int_v[i] = util::load8(sub!(chunk, 0, 8));
        }
        // NOTE the second condition prevents a trailing integer underflow
        //      (recognize that calc_index is not used after the last subtraction)
        calc_index = if rev == 0 || iter == 0 {
            calc_index + 512
        } else {
            calc_index - 512
        };

        transpose::transpose(&mut b_int_h, b_int_v);

        layer_ex(&mut r_int_h, &mut b_int_h, iter);
    }

    transpose::transpose(&mut r_int_v[0], r_int_h[0]);
    transpose::transpose(&mut r_int_v[1], r_int_h[1]);

    for (i, chunk) in r.chunks_mut(16).enumerate() {
        util::store8(sub!(mut chunk, 0, 8), r_int_v[0][i]);
        util::store8(sub!(mut chunk, 8, 8), r_int_v[1][i]);
    }
}

pub(crate) fn support_gen(s: &mut [Gf; SYS_N], c: &[u8; COND_BYTES]) {
    let mut a: Gf;
    let mut l = [[0u8; (1 << GFBITS) / 8]; GFBITS];

    for i in 0..(1 << GFBITS) {
        a = util::bitrev(i as Gf);

        for j in 0..GFBITS {
            l[j][i / 8] |= (((a >> j) & 1) << (i % 8)) as u8;
        }
    }

    for j in 0..GFBITS {
        #[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
        {
            apply_benes(&mut l[j], c, 0);
        }
        #[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
        {
            apply_benes(&mut l[j], c, 0);
        }
    }

    for i in 0..SYS_N {
        s[i] = 0;
        for j in (0..=(GFBITS - 1)).rev() {
            s[i] <<= 1;
            s[i] |= ((l[j][i / 8] >> (i % 8)) & 1) as u16;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;
    use crate::api::CRYPTO_PRIMITIVE;
    use std::convert::TryFrom;

    fn get(name: &str) -> Vec<u64> {
        let fullname = format!("{}_{}", CRYPTO_PRIMITIVE, name);
        crate::TestData::new().u64vec(&fullname)
    }

    fn get64(name: &str) -> [u64; 64] {
        <[u64; 64]>::try_from(get(name).as_slice()).unwrap()
    }

    #[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
    #[test]
    fn test_layer() {
        let mut data = [0u64; 64];
        let mut bits = [0u64; 32];
        for i in 0..64 {
            data[i] = 0xAAAA ^ (i as u64 * 17);
        }
        for i in 0..32 {
            bits[i] = (i as u64) << 3;
        }
        layer(&mut data, &bits, 4);
        assert_eq!(
            data,
            [
                0xAAAA, 0xAABB, 0xAA98, 0xAA89, 0xAAEE, 0xAADF, 0xAADC, 0xAAED, 0xAA22, 0xAA33,
                0xAA10, 0xAA41, 0xAA66, 0xAA57, 0xAA54, 0xAA25, 0xABBA, 0xAB8B, 0xAB88, 0xABF9,
                0xABFE, 0xABEF, 0xABCC, 0xAB1D, 0xAB32, 0xAB03, 0xAB00, 0xAB31, 0xAB76, 0xAB67,
                0xAB44, 0xA8D5, 0xA88A, 0xA89B, 0xA8F8, 0xA8E9, 0xA8CE, 0xA87F, 0xA83C, 0xA80D,
                0xA802, 0xA853, 0xA870, 0xA861, 0xA846, 0xA8B7, 0xA9B4, 0xA985, 0xA99A, 0xA9EB,
                0xA9E8, 0xA9D9, 0xA9DE, 0xA98F, 0xA92C, 0xA93D, 0xA912, 0xA923, 0xA960, 0xA951,
                0xA956, 0xAE47, 0xAEA4, 0xAEB5
            ]
        );
    }

    #[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
    #[test]
    fn test_layer_2() {
        let mut data_arg = get64("benes_layer_data_before");
        let bits_arg = get("benes_layer_bits");
        layer(&mut data_arg, &bits_arg, 0);
        let actual_data = data_arg;

        let expected_data = get64("benes_layer_data_after");

        assert_eq!(actual_data, expected_data);
    }

    #[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
    #[test]
    fn test_layer_in() {
        let data0_arg = get64("benes_layer_in_data0_before");
        let data1_arg = get64("benes_layer_in_data1_before");
        let mut data_arg = [data0_arg, data1_arg];
        let bits_arg = get64("benes_layer_in_bits");
        layer_in(&mut data_arg, &bits_arg, 0);
        let actual_data = data_arg;

        let expected_data0 = get64("benes_layer_in_data0_after");
        let expected_data1 = get64("benes_layer_in_data1_after");
        let expected_data = [expected_data0, expected_data1];

        assert_eq!(actual_data, expected_data);
    }

    #[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
    #[test]
    fn test_layer_ex() {
        let mut data = [[0u64; 64]; 2];
        let mut bits = [0u64; 64];

        for i in 0..64 {
            data[0][i] = 0xFC81 ^ (i as u64 * 17);
            data[1][i] = 0x9837 ^ (i as u64 * 3);
        }
        for i in 0..64 {
            bits[i] = (i as u64) << 3;
        }
        layer_ex(&mut data, &bits, 5);

        assert_eq!(
            data,
            [
                [
                    0xFC81, 0xFC90, 0xFCA3, 0xFCB2, 0xFCE5, 0xFCF4, 0xFCC7, 0xFCD6, 0xFC09, 0xFC18,
                    0xFC6B, 0xFC7A, 0xFC6D, 0xFC7C, 0xFC0F, 0xFC1E, 0xFD91, 0xFDA0, 0xFDB3, 0xFDC2,
                    0xFDF5, 0xFD44, 0xFD57, 0xFD26, 0xFD19, 0xFD68, 0xFD7B, 0xFD4A, 0xFD7D, 0xFD8C,
                    0xFD9F, 0xFEAE, 0xFEA1, 0xFEB0, 0xFEC3, 0xFED2, 0xFEC5, 0xFED4, 0xFE27, 0xFE36,
                    0xFE29, 0xFE38, 0xFE0B, 0xFE1A, 0xFE4D, 0xFE5C, 0xFFEF, 0xFFFE, 0xFFB1, 0xFFC0,
                    0xFFD3, 0xFFE2, 0xFFD5, 0xFFA4, 0xFFB7, 0xFF06, 0xFF39, 0xFF08, 0xFF1B, 0xFF6A,
                    0xFF5D, 0xF86C, 0xF87F, 0xF88E
                ],
                [
                    0x9837, 0x9834, 0x9831, 0x983E, 0x981B, 0x9818, 0x9805, 0x9802, 0x986F, 0x986C,
                    0x9869, 0x9816, 0x9833, 0x9830, 0x983D, 0x983A, 0x9887, 0x9884, 0x9881, 0x988E,
                    0x98AB, 0x98A8, 0x98D5, 0x98D2, 0x98BF, 0x98BC, 0x98B9, 0x98A6, 0x9883, 0x9880,
                    0x988D, 0x988A, 0x9857, 0x9854, 0x9851, 0x985E, 0x987B, 0x9878, 0x9865, 0x9862,
                    0x980F, 0x980C, 0x9809, 0x98B6, 0x9893, 0x9890, 0x989D, 0x989A, 0x9827, 0x9824,
                    0x9821, 0x982E, 0x980B, 0x9808, 0x9835, 0x9832, 0x985F, 0x985C, 0x9859, 0x9846,
                    0x9863, 0x9860, 0x986D, 0x986A
                ]
            ]
        );
    }

    #[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
    #[test]
    fn test_apply_benes() {
        let t = crate::TestData::new();
        let mut r_arg =
            <[u8; 512]>::try_from(t.u8vec("mceliece348864_benes_apply_benes_r_before")).unwrap();
        let bits_arg =
            <[u8; 5888]>::try_from(t.u8vec("mceliece348864_benes_apply_benes_bits")).unwrap();
        apply_benes(&mut r_arg, &bits_arg, 0);
        let actual_r = r_arg;
        let expected_r =
            <[u8; 512]>::try_from(t.u8vec("mceliece348864_benes_apply_benes_r_after")).unwrap();
        assert_eq!(actual_r, expected_r);
    }

    #[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
    #[test]
    fn test_apply_benes() {
        let t = crate::TestData::new();
        let mut r_arg =
            <[u8; 1024]>::try_from(t.u8vec("mceliece460896orlarger_benes_apply_benes_r_before"))
                .unwrap();
        let bits_arg =
            <[u8; COND_BYTES]>::try_from(t.u8vec("mceliece460896orlarger_benes_apply_benes_bits"))
                .unwrap(); // TODO actual array has wrong size of 12_800
        apply_benes(&mut r_arg, &bits_arg, 0);
        let actual_r = r_arg;
        let expected_r =
            <[u8; 1024]>::try_from(t.u8vec("mceliece460896orlarger_benes_apply_benes_r_after"))
                .unwrap();
        assert_eq!(actual_r, expected_r);
    }
}
