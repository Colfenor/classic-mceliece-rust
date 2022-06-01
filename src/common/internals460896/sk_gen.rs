//! Generation of secret key

use super::gf_mul::gf_mul_inplace;
use super::params::SYS_T;
use crate::common::gf13::{gf_inv, gf_iszero, gf_mul, Gf};

/// Take element `f` in `GF((2^m)^t)` and return minimal polynomial `out` of `f`
/// Returns 0 for success and -1 for failure
pub(crate) fn genpoly_gen(out: &mut [Gf; SYS_T], f: &[Gf; SYS_T]) -> isize {
    let mut mat = [[0u16; SYS_T]; SYS_T + 1];
    mat[0][0] = 1;

    mat[0][1..SYS_T].fill(0);

    for i in 0..SYS_T {
        mat[1][i] = f[i];
    }

    for j in 2..=SYS_T {
        let (left, right) = mat.split_at_mut(j);
        gf_mul_inplace(&mut right[0], &mut left[j - 1], f);
    }

    for j in 0..SYS_T {
        for k in (j + 1)..SYS_T {
            let mask = gf_iszero(mat[j][j]);

            let mut c = j;
            while c < SYS_T + 1 {
                mat[c][j] ^= mat[c][k] & mask;
                c += 1;
            }
        }

        if mat[j][j] == 0 {
            return -1;
        }

        let inv = gf_inv(mat[j][j]);

        for c in j..(SYS_T + 1) {
            mat[c][j] = gf_mul(mat[c][j], inv);
        }

        for k in 0..SYS_T {
            if k != j {
                let t = mat[j][k];

                for c in j..(SYS_T + 1) {
                    mat[c][k] ^= gf_mul(mat[c][j], t);
                }
            }
        }
    }

    out[0..SYS_T].copy_from_slice(&mat[SYS_T][0..SYS_T]);

    0
}
