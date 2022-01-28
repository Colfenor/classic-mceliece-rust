use crate::gf::{gf_add, gf_inv, gf_mul, Gf};
use crate::params::{SYS_N, SYS_T};
use crate::root::eval;
/* input: Goppa polynomial f, support L, received word r */
/* output: out, the syndrome of length 2t */
pub fn synd(out: &mut [Gf; SYS_T * 2], f: &mut [Gf; SYS_T + 1], l: &mut [Gf; SYS_N], r: &[u8]) {
    let (mut e, mut e_inv, mut c): (Gf, Gf, Gf);

    for j in 0..SYS_T * 2 {
        out[j] = 0;
    }

    for i in 0..SYS_N {
        c = ((r[i / 8] >> (i % 8)) & 1) as u16;

        e = eval(f, l[i]);
        e_inv = gf_inv(gf_mul(e, e));

        for j in 0..SYS_T * 2 {
            out[j] = gf_add(out[j], gf_mul(e_inv, c));
            e_inv = gf_mul(e_inv, l[i]);
        }
    }
}
