//! Generation of public key

use super::{GFBITS, GFMASK, PK_NROWS, PK_ROW_BYTES, SYS_N, SYS_T};
use crate::{
    common::{
        gf12::{bitrev, gf_inv, gf_mul, load_gf},
        internals348864::root::root,
        uint64_sort::uint64_sort,
    },
    macros::sub,
};

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
) -> i32 {
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
            return -1;
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
    const ROWS: usize = (PK_NROWS + 7) / 8;

    for i in 0..ROWS {
        for j in 0..8 {
            // NOTE: this loop is much very slow without optimization.
            //       test_pk_gen_2 takes 126s, but 4s with opt-level=1.
            let row = i * 8 + j;

            if row >= PK_NROWS {
                break;
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
                if k == row {
                    continue;
                }

                let mut mask = mat[k][i] >> j;
                mask &= 1;
                mask = 0u8.wrapping_sub(mask);

                for c in 0..(SYS_N / 8) {
                    mat[k][c] ^= mat[row][c] & mask;
                }
            }
        }
    }

    #[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
    let tail = PK_NROWS % 8;
    #[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
    const INNER_PK_ACCESSES: usize = ((SYS_N / 8 - 1) - (PK_NROWS - 1) / 8) + 1;

    for i in 0..PK_NROWS {
        #[cfg(not(any(feature = "mceliece6960119", feature = "mceliece6960119f")))]
        pk[i * PK_ROW_BYTES..(i + 1) * PK_ROW_BYTES]
            .copy_from_slice(&mat[i][PK_NROWS / 8..PK_NROWS / 8 + PK_ROW_BYTES]);

        #[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
        for (idx, j) in ((PK_NROWS - 1) / 8..SYS_N / 8 - 1).enumerate() {
            pk[i * INNER_PK_ACCESSES + idx] = (mat[i][j] >> tail) | (mat[i][j + 1] << (8 - tail));
        }
        #[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
        {
            pk[(i + 1) * INNER_PK_ACCESSES - 1] = mat[i][SYS_N / 8 - 1] >> tail;
        }
    }

    0
}
