use crate::{
    gf::{gf_inv, gf_mul},
    macros::sub,
    params::{GFBITS, GFMASK, PK_NROWS, PK_ROW_BYTES, SYS_N, SYS_T},
    root::root,
    uint64_sort::uint64_sort,
    util::{bitrev, load_gf},
};
use std::error;

#[cfg(any(
    feature = "mceliece348864f",
    feature = "mceliece460896f",
    feature = "mceliece6688128f",
    feature = "mceliece6960119f",
    feature = "mceliece8192128f"
))]
use crate::util::{load8, store8};

/// Return number of trailing zeros of the non-zero input `input`
#[cfg(any(
    feature = "mceliece348864f",
    feature = "mceliece460896f",
    feature = "mceliece6688128f",
    feature = "mceliece6960119f",
    feature = "mceliece8192128f"
))]
fn ctz(input: u64) -> i32 {
    let (mut m, mut r) = (0i32, 0i32);

    for i in 0..64 {
        let b = ((input >> i) & 1) as i32;
        m |= b;
        r += (m ^ 1) & (b ^ 1);
    }

    r
}

/// Takes two 16-bit integers and determines whether they are equal (u64::MAX) or different (0)
#[cfg(any(
    feature = "mceliece348864f",
    feature = "mceliece460896f",
    feature = "mceliece6688128f",
    feature = "mceliece6960119f",
    feature = "mceliece8192128f"
))]
fn same_mask(x: u16, y: u16) -> u64 {
    let mut mask = (x ^ y) as u64;
    mask = mask.wrapping_sub(1);
    mask >>= 63;
    mask = 0u64.wrapping_sub(mask);

    mask
}

/// Move columns in matrix `mat`
#[cfg(any(
    feature = "mceliece348864f",
    feature = "mceliece460896f",
    feature = "mceliece6688128f",
    feature = "mceliece6960119f",
    feature = "mceliece8192128f"
))]
fn mov_columns(
    mat: &mut [[u8; SYS_N / 8]; PK_NROWS],
    pi: &mut [i16; 1 << GFBITS],
    pivots: &mut u64,
) -> Result<i32, Box<dyn error::Error>> {
    let mut buf = [0u64; 64];
    let mut ctz_list = [0u64; 32];

    let row = PK_NROWS - 32;
    let block_idx = row / 8;

    #[cfg(feature = "mceliece6960119f")]
    let tail = row % 8;
    #[cfg(feature = "mceliece6960119f")]
    let mut tmp = [0u8; 9];

    #[cfg(not(feature = "mceliece6960119f"))]
    for i in 0..32 {
        buf[i] = load8(sub!(mat[row + i], block_idx, 8));
    }

    #[cfg(feature = "mceliece6960119f")]
    for i in 0..32 {
        for j in 0..9 {
            tmp[j] = mat[row + i][block_idx + j];
        }
        for j in 0..8 {
            tmp[j] = (tmp[j] >> tail) | (tmp[j + 1] << (8 - tail));
        }

        buf[i] = load8(sub!(tmp, 0, 8));
    }

    // Compute the column indices of pivots by Gaussian elimination.
    // The indices are stored in ctz_list

    *pivots = 0;
    for i in 0..32 {
        let mut t = buf[i];
        for j in i + 1..32 {
            t |= buf[j];
        }

        if t == 0 {
            return Ok(-1); // return if buf is not full rank
        }

        ctz_list[i] = ctz(t) as u64;
        let s = ctz_list[i] as usize;

        *pivots |= 1u64 << s;

        for j in i + 1..32 {
            let mut mask = (buf[i] >> s) & 1;
            mask = mask.wrapping_sub(1);
            buf[i] ^= buf[j] & mask;
        }

        for j in i + 1..32 {
            let mut mask = (buf[j] >> s) & 1;
            mask = 0u64.wrapping_sub(mask);
            buf[j] ^= buf[i] & mask;
        }
    }

    // updating permutation
    for j in 0..32 {
        for k in j + 1..64 {
            let mut d = (pi[row + j] ^ pi[row + k]) as u64;
            d &= same_mask(k as u16, ctz_list[j] as u16);
            pi[row + j] ^= d as i16;
            pi[row + k] ^= d as i16;
        }
    }

    // moving columns of mat according to the column indices of pivots
    #[cfg(not(feature = "mceliece6960119f"))]
    for i in 0..PK_NROWS {
        let mut t = load8(sub!(mat[i], block_idx, 8));

        for j in 0..32 {
            let mut d: u64 = t >> j;
            d ^= t >> ctz_list[j];
            d &= 1;

            t ^= d << ctz_list[j];
            t ^= d << j;
        }

        store8(sub!(mut mat[i], block_idx, 8), t);
    }

    #[cfg(feature = "mceliece6960119f")]
    for i in 0..PK_NROWS {
        for k in 0..9 {
            tmp[k] = mat[i][block_idx + k];
        }
        for k in 0..8 {
            tmp[k] = (tmp[k] >> tail) | (tmp[k + 1] << (8 - tail));
        }

        let mut t = load8(sub!(tmp, 0, 8));

        for j in 0..32 {
            let mut d = t >> j;
            d ^= t >> ctz_list[j];
            d &= 1;

            t ^= d << ctz_list[j];
            t ^= d << j;
        }

        store8(sub!(mut tmp, 0, 8), t);

        mat[i][block_idx + 8] = (mat[i][block_idx + 8] >> tail << tail) | (tmp[7] >> (8 - tail));
        mat[i][block_idx + 0] = (tmp[0] << tail) | (mat[i][block_idx] << (8 - tail) >> (8 - tail));

        for k in (1..=7).rev() {
            mat[i][block_idx + k] = (tmp[k] << tail) | (tmp[k - 1] >> (8 - tail));
        }
    }

    Ok(0)
}

/// Public key generation. Generate the public key `pk`,
/// permutation `pi` and pivot element `pivots` based on the
/// secret key `sk` and permutation `perm` provided.
/// `pk` has `max(1 << GFBITS, SYS_N)` elements which is
/// 4096 for mceliece348864 and 8192 for mceliece8192128.
/// `sk` has `2 * SYS_T` elements and perm `1 << GFBITS`.
pub(crate) fn pk_gen(
    pk: &mut [u8; PK_NROWS * PK_ROW_BYTES],
    sk: &[u8; 2 * SYS_T],
    perm: &[u32; 1 << GFBITS],
    pi: &mut [i16; 1 << GFBITS],
    #[cfg(any(
        feature = "mceliece348864f",
        feature = "mceliece460896f",
        feature = "mceliece6688128f",
        feature = "mceliece6960119f",
        feature = "mceliece8192128f"
    ))]
    pivots: &mut u64,
) -> Result<i32, Box<dyn error::Error>> {
    let mut buf = [0u64; 1 << GFBITS];
    let mut mat = [[0u8; SYS_N / 8]; PK_NROWS];

    let mut g = [0u16; SYS_T + 1];
    let mut l = [0u16; SYS_N];
    let mut inv = [0u16; SYS_N];

    g[SYS_T] = 1;
    for (i, chunk) in sk.chunks(2).take(SYS_T).enumerate() {
        g[i] = load_gf(sub!(chunk, 0, 2));
    }

    for i in 0..(1 << GFBITS) {
        buf[i] = perm[i] as u64;
        buf[i] <<= 31;
        buf[i] |= i as u64;
    }

    uint64_sort(sub!(mut buf, 0, 1 << GFBITS, u64));

    for i in 1..(1 << GFBITS) {
        if buf[i - 1] >> 31 == buf[i] >> 31 {
            return Ok(-1);
        }
    }

    for i in 0..(1 << GFBITS) {
        pi[i] = buf[i] as i16 & GFMASK as i16;
    }

    for i in 0..SYS_N {
        l[i] = bitrev(pi[i] as u16);
    }

    root(&mut inv, &g, &l);

    for i in 0..SYS_N {
        inv[i] = gf_inv(inv[i]);
    }

    for i in 0..SYS_T {
        for j in (0..SYS_N).step_by(8) {
            for k in 0..GFBITS {
                let mut b = ((inv[j + 7] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 6] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 5] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 4] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 3] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 2] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 1] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 0] >> k) & 1) as u8;

                mat[i * GFBITS + k][j / 8] = b;
            }
        }
        for j in 0..SYS_N {
            inv[j] = gf_mul(inv[j], l[j]);
        }
    }

    // gaussian elimination
    for i in 0..(PK_NROWS + 7) / 8 {
        for j in 0..8 {
            // TODO this loop is much slower than in C
            let row = i * 8 + j;

            if row >= PK_NROWS {
                break;
            }

            #[cfg(any(
                feature = "mceliece348864f",
                feature = "mceliece460896f",
                feature = "mceliece6688128f",
                feature = "mceliece6960119f",
                feature = "mceliece8192128f"
            ))]
            {
                if row == PK_NROWS - 32 {
                    if mov_columns(&mut mat, pi, pivots)? != 0 {
                        return Ok(-1);
                    }
                }
            }

            for k in (row + 1)..PK_NROWS {
                let mut mask = mat[row][i] ^ mat[k][i];
                mask >>= j;
                mask &= 1;
                mask = 0u8.wrapping_sub(mask);

                for c in 0..SYS_N / 8 {
                    mat[row][c] ^= mat[k][c] & mask;
                }
            }

            if ((mat[row][i] >> j) & 1) == 0 {
                return Ok(-1);
            }

            for k in 0..PK_NROWS {
                if k != row {
                    let mut mask = mat[k][i] >> j;
                    mask &= 1;
                    mask = 0u8.wrapping_sub(mask);

                    for c in 0..(SYS_N / 8) {
                        mat[k][c] ^= mat[row][c] & mask;
                    }
                }
            }
        }
    }

    #[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
    let tail = PK_NROWS % 8;
    #[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
    const INNER_PK_ACCESSES: usize = ((SYS_N / 8 - 1) - (PK_NROWS - 1) / 8) + 1;

    for i in 0..PK_NROWS {
        // TODO rewrite with copy_from_slice
        #[cfg(not(any(feature = "mceliece6960119", feature = "mceliece6960119f")))]
        for j in 0..PK_ROW_BYTES {
            pk[i * PK_ROW_BYTES + j] = mat[i][PK_NROWS / 8 + j];
        }

        #[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
        for (idx, j) in ((PK_NROWS - 1) / 8..SYS_N / 8 - 1).enumerate() {
            pk[i * INNER_PK_ACCESSES + idx] = (mat[i][j] >> tail) | (mat[i][j + 1] << (8 - tail));
        }
        #[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
        {
            pk[(i + 1) * INNER_PK_ACCESSES - 1] = mat[i][SYS_N / 8 - 1] >> tail;
        }
    }

    Ok(0)
}

#[cfg(test)]
mod tests {
    #[cfg(any(
        feature = "mceliece348864f",
        feature = "mceliece460896f",
        feature = "mceliece6688128f",
        feature = "mceliece6960119f",
        feature = "mceliece8192128f"
    ))]
    use super::*;
    #[cfg(feature = "mceliece8192128f")]
    use crate::api::CRYPTO_PUBLICKEYBYTES;

    #[test]
    #[cfg(any(
        feature = "mceliece348864f",
        feature = "mceliece460896f",
        feature = "mceliece6688128f",
        feature = "mceliece6960119f",
        feature = "mceliece8192128f"
    ))]
    fn test_ctz() {
        const EXPECTED: [i32; 180] = [
            64, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2,
            0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0,
            1, 0, 2, 0, 1, 0, 6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1,
            0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0,
            2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 7, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
            0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0,
            1, 0, 4, 0, 1, 0,
        ];
        for i in 0..180 {
            assert_eq!(ctz(i as u64), EXPECTED[i]);
        }
    }

    #[test]
    #[cfg(any(
        feature = "mceliece348864f",
        feature = "mceliece460896f",
        feature = "mceliece6688128f",
        feature = "mceliece6960119f",
        feature = "mceliece8192128f"
    ))]
    fn test_same_mask() {
        const EXPECTED: [u64; 25] = [
            0xFFFFFFFFFFFFFFFF,
            0,
            0,
            0,
            0,
            0,
            0xFFFFFFFFFFFFFFFF,
            0,
            0,
            0,
            0,
            0,
            0xFFFFFFFFFFFFFFFF,
            0,
            0,
            0,
            0,
            0,
            0xFFFFFFFFFFFFFFFF,
            0,
            0,
            0,
            0,
            0,
            0xFFFFFFFFFFFFFFFF,
        ];
        for i in 0..5 {
            for j in 0..5 {
                assert_eq!(same_mask(i as u16, j as u16), EXPECTED[i * 5 + j]);
            }
        }
    }

    #[test]
    #[cfg(feature = "mceliece8192128f")]
    fn test_mov_columns() -> Result<(), Box<dyn error::Error>> {
        const COLS: usize = SYS_N / 8;

        // input data
        let mut mat = [[0u8; COLS]; PK_NROWS];
        let mat_data = crate::TestData::new().u8vec("mceliece8192128f_mat_before");
        assert_eq!(mat_data.len(), PK_NROWS * COLS);

        for row in 0..PK_NROWS {
            for col in 0..COLS {
                mat[row][col] = mat_data[row * COLS + col];
            }
        }

        let mut pi = crate::TestData::new().i16vec("mceliece8192128f_pi_before");
        let mut pivots = 0u64;

        // generated actual result
        mov_columns(
            <&mut [[u8; COLS]; PK_NROWS]>::try_from(&mut *mat)?,
            <&mut [i16; 1 << GFBITS]>::try_from(pi.as_mut_slice())?,
            &mut pivots,
        )?;

        // expected data
        let mut mat_expected = Box::new([[0u8; COLS]; PK_NROWS]);
        let mat_expected_data = crate::TestData::new().u8vec("mceliece8192128f_mat_expected");

        for row in 0..PK_NROWS {
            for col in 0..COLS {
                mat_expected[row][col] = mat_expected_data[row * COLS + col];
            }
        }

        let pi_expected = crate::TestData::new().i16vec("mceliece8192128f_pi_expected");
        let pivots_expected = 8053063679u64;

        // comparison
        assert_eq!(*mat.into_boxed_slice(), *mat_expected);
        assert_eq!(pi, pi_expected);
        assert_eq!(pivots, pivots_expected);

        Ok(())
    }

    #[test]
    #[cfg(feature = "mceliece8192128f")]
    fn test_pk_gen_1() {
        let sk_data = crate::TestData::new().u8vec("mceliece8192128f_pk_gen_sk_input");
        let perm_data = crate::TestData::new().u32vec("mceliece8192128f_pk_gen_perm_input");

        let mut pk = vec![0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk = [0u8; 2 * SYS_T];
        let mut perm = [0u32; 1 << GFBITS];
        let mut pi = [0i16; if (1 << GFBITS) > SYS_N {
            1 << GFBITS
        } else {
            SYS_N
        }];
        let mut pivots = 0u64;

        assert_eq!(sk_data.len(), sk.len());
        assert_eq!(perm_data.len(), perm.len());

        sk.copy_from_slice(sk_data.as_slice());
        perm.copy_from_slice(perm_data.as_slice());

        pk_gen(&mut pk, &mut sk, &mut perm, &mut pi, &mut pivots);

        let pk_expected = crate::TestData::new().u8vec("mceliece8192128f_pk_gen_pk_expected");
        let sk_expected = crate::TestData::new().u8vec("mceliece8192128f_pk_gen_sk_expected");
        let perm_expected = crate::TestData::new().u32vec("mceliece8192128f_pk_gen_perm_expected");
        let pi_expected = crate::TestData::new().i16vec("mceliece8192128f_pk_gen_pi_expected");

        assert_eq!(pk, pk_expected.as_slice());
        assert_eq!(sk, sk_expected.as_slice());
        assert_eq!(perm, perm_expected.as_slice());
        assert_eq!(pi, pi_expected.as_slice());
        assert_eq!(pivots, 0x1DFFFFFFF);
    }

    #[test]
    #[cfg(feature = "mceliece8192128f")]
    fn test_pk_gen_2() {
        // NOTE expected pk_data of previous testcase becomes input for this one
        let pk_data = crate::TestData::new().u8vec("mceliece8192128f_pk_gen_pk_expected");
        let sk_data = crate::TestData::new().u8vec("mceliece8192128f_pk_gen_sk2_input");
        let perm_data = crate::TestData::new().u32vec("mceliece8192128f_pk_gen_perm2_input");
        let pi_data = crate::TestData::new().i16vec("mceliece8192128f_pk_gen_pi2_input");

        let mut pk = vec![0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk = [0u8; 2 * SYS_T];
        let mut perm = [0u32; 1 << GFBITS];
        let mut pi = [0i16; if (1 << GFBITS) > SYS_N {
            1 << GFBITS
        } else {
            SYS_N
        }];
        let mut pivots = 0x1DFFFFFFF_u64;

        assert_eq!(pk_data.len(), pk.len());
        assert_eq!(sk_data.len(), sk.len());
        assert_eq!(perm_data.len(), perm.len());
        assert_eq!(pi_data.len(), pi.len());

        pk.copy_from_slice(pk_data.as_slice());
        sk.copy_from_slice(sk_data.as_slice());
        perm.copy_from_slice(perm_data.as_slice());
        pi.copy_from_slice(pi_data.as_slice());

        pk_gen(&mut pk, &mut sk, &mut perm, &mut pi, &mut pivots);

        let pk_expected = crate::TestData::new().u8vec("mceliece8192128f_pk_gen_pk2_expected");
        let sk_expected = crate::TestData::new().u8vec("mceliece8192128f_pk_gen_sk2_expected");
        let perm_expected = crate::TestData::new().u32vec("mceliece8192128f_pk_gen_perm2_expected");
        let pi_expected = crate::TestData::new().i16vec("mceliece8192128f_pk_gen_pi2_expected");

        assert_eq!(pivots, 0xffffffff);
        assert_eq!(sk, sk_expected.as_slice());
        assert_eq!(pi, pi_expected.as_slice());
        assert_eq!(perm, perm_expected.as_slice());
        assert_eq!(pk, pk_expected.as_slice());
    }
}
