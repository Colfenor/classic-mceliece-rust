use crate::gf::{gf_add, gf_inv, gf_mul, Gf};
use crate::params::{SYS_N, SYS_T};
use crate::root::eval;
/* input: Goppa polynomial f, support L, received word r */
/* output: out, the syndrome of length 2t */
fn synd(out: &mut [Gf; SYS_T * 2], f: &mut [Gf; SYS_T + 1], L: &mut [Gf; SYS_N], r: &[u8]) {
    let (mut i, mut j): (usize, usize);
    let (mut e, mut e_inv, mut c): (Gf, Gf, Gf);

    j = 0;
    while j < SYS_T * 2 {
        out[j] = 0;
        j += 1;
    }

    i = 0;
    while i < SYS_N {
        c = ((r[i / 8] >> (i % 8)) & 1) as u16;

        e = eval(f, L[i]);
        e_inv = gf_inv(gf_mul(e, e));

        j = 0;
        while j < SYS_T * 2 {
            out[j] = gf_add(out[j], gf_mul(e_inv, c));
            e_inv = gf_mul(e_inv, L[i]);

            j += 1;
        }
        i += 1;
    }
}
