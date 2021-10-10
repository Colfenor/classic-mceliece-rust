/*
  This file is for evaluating a polynomial at one or more field elements
*/

use crate::gf::{gf_add, gf_mul, Gf, SYS_N, SYS_T};

pub fn eval(f: &mut [Gf; SYS_T + 1], a: Gf) -> Gf {
    let mut i: usize;
    let mut r: Gf = f[SYS_T];

    i = SYS_T - 1;
    while i >= 0 {
        r = gf_mul(r, a);
        r = gf_add(r, f[i]);

        i -= 1;
    }
    r
}

/* input: polynomial f and list of field elements L */
/* output: out = [ f(a) for a in L ] */
fn root(out: &mut [Gf; SYS_N], f: &mut [Gf; SYS_T + 1], L: &mut [Gf; SYS_T]) {
    let mut i: usize = 0;

    while i < SYS_N {
        out[i] = eval(f, L[i]);

        i += 1;
    }
}
