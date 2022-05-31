//! Generation of secret key

use crate::gf::{gf_inv, gf_iszero, gf_mul, gf_mul_inplace, Gf};
use crate::params::SYS_T;

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

#[cfg(test)]
#[cfg(all(feature = "mceliece8192128f", test))]
mod tests {
    use super::*;
    use crate::macros::sub;

    #[test]
    fn test_genpoly_gen() {
        assert_eq!(SYS_T, 128);

        let input_src =
            crate::TestData::new().u16vec("mceliece8192128f_sk_gen_genpoly_1st_round_input");
        let first_round_input = sub!(input_src, 0, 128, u16);
        let first_round_output =
            crate::TestData::new().u16vec("mceliece8192128f_sk_gen_genpoly_1st_round_output");

        let mut output = [0u16; SYS_T];

        genpoly_gen(&mut output, first_round_input);

        assert_eq!(&output, first_round_output.as_slice());
    }
}
