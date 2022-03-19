use crate::{
    gf::{gf_inv, gf_mul},
    params::{GFBITS, GFMASK, PK_NROWS, PK_ROW_BYTES, SYS_N, SYS_T},
    root::root,
    uint64_sort::uint64_sort,
    util::{bitrev, load8, load_gf, store8},
};

/// Return number of trailing zeros of the non-zero input `input`
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
fn same_mask(x: u16, y: u16) -> u64 {
    let mut mask = (x ^ y) as u64;
    mask = mask.wrapping_sub(1);
    mask >>= 63;
    mask = 0u64.wrapping_sub(mask);

    mask
}

/// Move columns in matrix `mat`
fn mov_columns(
    mat: &mut [[u8; SYS_N / 8]; PK_NROWS],
    pi: &mut [i16; 1 << GFBITS],
    pivots: &mut u64,
) -> i32 {
    let mut buf = [0u64; 64];
    let mut ctz_list = [0u64; 32];

    let row = PK_NROWS - 32;
    let block_idx = row / 8;
    let mut mat_row: [u8; SYS_N / 8];

    for i in 0..32 {
        mat_row = mat[row + i];
        buf[i] = load8(&mat_row[block_idx..block_idx + 8]);
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
            return -1; // return if buf is not full rank
        }

        ctz_list[i] = ctz(t) as u64;
        let s = ctz_list[i] as i32;

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
    for i in 0..PK_NROWS {
        let mut t = load8(&mat[i][block_idx..block_idx + 8]);

        for j in 0..32 {
            let mut d: u64 = t >> j;
            d ^= t >> ctz_list[j];
            d &= 1;

            t ^= d << ctz_list[j];
            t ^= d << j;
        }

        store8(&mut mat[i][block_idx..block_idx + 8], t);
    }

    0
}

/// Public key generation. Generate the public key `pk`,
/// permutation `pi` and pivot element `pivots` based on the 
/// secret key `sk` and permutation `perm` provided.
pub(crate) fn pk_gen(
    pk: &mut [u8],
    sk: &[u8],
    perm: &[u32],
    pi: &mut [i16; 1 << GFBITS],
    #[cfg(any(feature = "mceliece348864f", feature = "mceliece460896f", feature = "mceliece6688128f", feature = "mceliece6960119f", feature = "mceliece8192128f"))]
    pivots: &mut u64,
) -> i32 {
    let mut buf = [0u64; 1 << GFBITS];
    let mut mat = [[0u8; SYS_N / 8]; PK_NROWS];

    let mut g = [0u16; SYS_T + 1];
    let mut l = [0u16; SYS_N];
    let mut inv = [0u16; SYS_N];

    g[SYS_T] = 1;
    let mut i = 0;
    for chunk in sk.chunks(2) {
        g[i] = load_gf(chunk);
        i += 1;
        if i == SYS_T {
            break;
        }
    }

    for i in 0..(1 << GFBITS) {
        buf[i] = perm[i] as u64;
        buf[i] <<= 31;
        buf[i] |= i as u64;
    }

    uint64_sort(&mut buf, 1 << GFBITS);

    for i in 1..(1 << GFBITS) {
        if buf[i - 1] >> 31 == buf[i] >> 31 {
            return -1;
        }
    }

    for i in 0..(1 << GFBITS) {
        pi[i] = (buf[i] & GFMASK as u64) as i16;
    }

    for i in 0..SYS_N {
        l[i] = bitrev(pi[i] as u16);
    }

    root(&mut inv, &mut g, &mut l);

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
            let row = i * 8 + j;

            if row >= PK_NROWS {
                break;
            }

            #[cfg(any(feature = "mceliece348864f", feature = "mceliece460896f", feature = "mceliece6688128f", feature = "mceliece6960119f", feature = "mceliece8192128f"))]
            {
                if row == PK_NROWS - 32 && mov_columns(&mut mat, pi, pivots) != 0 {
                    return -1;
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
                return -1;
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

    for i in 0..PK_NROWS {
        for j in 0..PK_ROW_BYTES {
            pk[i * PK_ROW_BYTES + j] = mat[i][PK_NROWS / 8 + j];
        }
    }
    return 0;
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "mceliece8192128f", test))]
    use super::*;
    #[cfg(all(feature = "mceliece8192128f", test))]
    use crate::api::CRYPTO_PUBLICKEYBYTES;

    #[test]
    #[cfg(all(feature = "mceliece8192128f", test))]
    fn test_pk_gen() {
        let mut test_perm = crate::TestData::new().u32vec("mceliece8192128f_pk_gen_perm_input");
        assert_eq!(test_perm.len(), 1 << GFBITS);

        let mut sk = crate::TestData::new().u8vec("mceliece8192128f_pk_gen_perm_sk");

        let mut pivots = 0u64;
        let mut pi = [0i16; 1 << GFBITS];
        let mut pk = vec![0u8; CRYPTO_PUBLICKEYBYTES];

        pk_gen(&mut pk, &mut sk, &mut test_perm, &mut pi, &mut pivots);

        let pk_compare = crate::TestData::new().u8vec("mceliece8192128f_pk_gen_pk_expected");
        assert_eq!(pk, pk_compare);
    }
}
