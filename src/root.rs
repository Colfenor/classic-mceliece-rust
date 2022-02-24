/*
  This file is for evaluating a polynomial at one or more field elements
*/

use crate::{
    gf::{gf_add, gf_mul, Gf},
    params::{SYS_N, SYS_T},
};

/// Evaluate polynomial `f` with argument `a`.
/// Thus it returns `f(a)` in symbolic notation.
pub(crate) fn eval(f: &[Gf; SYS_T + 1], a: Gf) -> Gf {
    let mut r: Gf = f[SYS_T];

    for i in (0..=SYS_T - 1).rev() {
        r = gf_mul(r, a);
        r = gf_add(r, f[i]);
    }
    r
}

/// Given polynomial `f` and a list of field elements `l`,
/// return the roots `out` satisfying `[ f(a) for a in L ]`
pub(crate) fn root(out: &mut [Gf; SYS_N], f: &mut [Gf; SYS_T + 1], l: &[Gf; SYS_N]) {
    for i in 0..SYS_N {
        out[i] = eval(f, l[i]);
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "mceliece8192128f", test))]
    use super::*;

    #[test]
    #[cfg(feature = "mceliece8192128f")]
    fn test_root() {
        let mut g = [1u16; SYS_T + 1];
        let mut l = [0u16; SYS_N];
        let mut inv = [0u16; SYS_N];

        for i in 0..l.len() {
            l[i] = i as u16;
            inv[i] = 0;
        }

        root(&mut inv, &mut g, &mut l);

        let expected = crate::TestData::new().u16vec("mceliece8192128f_root_inv_expected");
        assert_eq!(expected, inv);
    }
}
