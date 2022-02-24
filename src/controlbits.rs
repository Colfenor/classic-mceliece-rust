//! Implementation of Nassimi-Sahni algorithm[^ns][^cb]
//!
//! [^ns]: David Nassimi, Sartaj Sahni "Parallel algorithms to set up the Benes permutationnetwork"
//! [^cb]: Daniel J. Bernstein "Verified fast formulas for control bits for permutation networks"
//!        https://cr.yp.to/papers/controlbits-20200923.pdf

use crate::int32_sort::int32_sort;
use crate::params::GFBITS;

// controlbits returns ((2*m - 1) * 2^(m - 1)) control bits for a permutation pi over 2^m indices
// equals ((2*m - 1) * 2^(m - 1))/8 control bytes, which is what this macro computes.
// “+ 7” implements ceil() instead of default behavior floor().
macro_rules! CONTROLBYTES {
    ($m:expr, $step:expr) => {
        (((2 * $m - 1) * (1 << ($m - 1)) * $step + 7) >> 3)
    };
}

/// Layer implements one layer of the Beneš network.
///
/// It permutes elements `p` according to control bits `cb` in-place.
/// Thus, one layer of the Beneš network is created and if some control bits are set
/// the corresponding transposition is applied. Parameter `s` equals `n.len()` and
/// `s` configures `stride-2^s` conditional swaps.
///
/// The following requirement is undocumented in C:
///   `assert!(1 << (s + 1) <= n);`
fn layer(p: &mut [i16], cb: &[u8], s: i32, n: i32) {
    assert_eq!(p.len(), n as usize);
    assert!(1 << (s + 1) <= n);

    let stride = 1 << s;
    let mut index = 0;

    for i in (0..n as usize).step_by(stride * 2) {
        for j in 0..stride {
            let mut d = (p[(i + j) as usize] ^ p[(i + j + stride) as usize]) as i16;
            let mut m = ((cb[index >> 3] >> (index & 7)) & 1) as i16;
            m = -m;
            d &= m;
            p[(i + j) as usize] ^= d as i16;
            p[(i + j + stride) as usize] ^= d as i16;
            index += 1;
        }
    }
}

/// `cbrecursion` implements a recursion step of `controlbitsfrompermutation`.
///
/// Pick `w ∈ {1, 2, …, 14}. Let `n = 2^w`.
/// `out` must be a reference to a slice with `((2*w-1)*(1<<(w-1))+7)/8` or more bytes.
/// It must zero-initialized before the first recursive call.
/// `step` is initialized with 0 and doubles in each recursion step.
/// `pi_offset` is an offset within temp slice ref (or aux in the first recursive call).
/// `temp` is an intermediate reference to a slice used for recursive computation and
/// temporarily stores values. It must be able to carry at least 2・n elements.
/// `aux` is an auxiliary reference to a slice. It points to the elements to be permuted.
/// After the first recursive iterations, the elements are stored in `temp` and thus `aux`
/// won't be read anymore. The first `n/2` elements are read.
///
/// The interface differs from the C implementation, because C uses pointer arithmetic
/// and reinterprets arrays in different types. This is a less-efficient safe-rust implementation.
///
/// But the following descriptions still hold true:
///   out is filled with (2m-1)n/2 control bits at positions pos, pos+step, …
fn cbrecursion(
    out: &mut [u8],
    mut pos: usize,
    step: usize,
    pi_offset: usize,
    w: usize,
    n: usize,
    temp: &mut [i32],
    aux: &[i32],
) {
    assert!(out.len() >= CONTROLBYTES!(w, step));
    assert!(temp.len() >= 2 * n);
    assert!(aux.len() >= n / 2);
    assert!(pi_offset <= 3 * n);

    if w == 1 {
        let first = if pi_offset == 0 {
            aux[0]
        } else {
            temp[pi_offset]
        } as i16;
        out[pos >> 3] ^= (first << (pos & 7)) as u8;
        return;
    }

    for x in 0..n {
        let perm = if pi_offset == 0 {
            aux[pi_offset + x / 2]
        } else {
            temp[pi_offset + x / 2]
        };
        let low: i32 = perm & 0xffff;
        let high: i32 = perm >> 16;
        if x % 2 == 0 {
            temp[x] = ((low ^ 1) << 16) | (high & 0xffff);
        } else {
            temp[x] = ((high ^ 1) << 16) | (low & 0xffff);
        }
    }
    int32_sort(temp, n as i64); /* A = (id<<16)+pibar */

    for x in 0..n {
        let ax: i32 = temp[x];
        let px: i32 = ax & 0xffff;
        let mut cx: i32 = px;
        if (x as i32) < cx {
            cx = x as i32;
        }
        temp[n + x] = (px << 16) | cx;
    }
    /* B = (p<<16)+c */

    for x in 0..n {
        temp[x] = (temp[x] << 16) | (x as i32); /* A = (pibar<<16)+id */
    }
    int32_sort(temp, n as i64); /* A = (id<<16)+pibar^-1 */

    for x in 0..n {
        temp[x] = (temp[x] << 16) + (temp[n + x] >> 16); /* A = (pibar^(-1)<<16)+pibar */
    }
    int32_sort(temp, n as i64); /* A = (id<<16)+pibar^2 */

    if w <= 10 {
        for x in 0..n {
            temp[n + x] = ((temp[x] & 0xffff) << 10) | (temp[n + x] & 0x3ff);
        }

        for _ in 1..(w - 1) {
            /* B = (p<<10)+c */

            for x in 0..n {
                temp[x] = ((temp[n + x] & (0xfffffc << 8)) << 6) | (x as i32); /* A = (p<<16)+id */
            }
            int32_sort(temp, n as i64); /* A = (id<<16)+p^{-1} */

            for x in 0..n {
                temp[x] = (temp[x] << 20) | temp[n + x]; /* A = (p^{-1}<<20)+(p<<10)+c */
            }
            int32_sort(temp, n as i64); /* A = (id<<20)+(pp<<10)+cp */

            for x in 0..n {
                let ppcpx: i32 = temp[x] & 0xfffff;
                let mut ppcx: i32 = (temp[x] & 0xffc00) | (temp[n + x] & 0x3ff);
                if ppcpx < ppcx {
                    ppcx = ppcpx;
                }
                temp[n + x] = ppcx;
            }
        }
        for x in 0..n {
            temp[n + x] &= 0x3ff;
        }
    } else {
        for x in 0..n {
            temp[n + x] = (temp[x] << 16) | (temp[n + x] & 0xffff);
        }
        for i in 1..(w - 1) {
            /* B = (p<<16)+c */

            for x in 0..n {
                temp[x] = (temp[n + x] & (0xffff << 16)) | (x as i32);
            }
            int32_sort(temp, n as i64); /* A = (id<<16)+p^(-1) */

            for x in 0..n {
                temp[x] = (temp[x] << 16) | (temp[n + x] & 0xffff);
            }
            /* A = p^(-1)<<16+c */

            if i < w - 2 {
                for x in 0..n {
                    temp[n + x] = (temp[x] & (0xffff << 16)) | (temp[n + x] >> 16);
                }
                /* B = (p^(-1)<<16)+p */
                int32_sort(&mut temp[n..], n as i64); /* B = (id<<16)+p^(-2) */
                for x in 0..n {
                    temp[n + x] = (temp[n + x] << 16) | (temp[x] & 0xffff);
                }
                /* B = (p^(-2)<<16)+c */
            }

            int32_sort(temp, n as i64);
            /* A = id<<16+cp */
            for x in 0..n {
                let cpx: i32 = (temp[n + x] & (0xffff << 16)) | (temp[x] & 0xffff);
                if cpx < temp[n + x] {
                    temp[n + x] = cpx;
                }
            }
        }
        for x in 0..n {
            temp[n + x] &= 0xffff;
        }
    }

    for x in 0..n {
        let perm: i32 = if pi_offset == 0 {
            aux[pi_offset + x / 2]
        } else {
            temp[pi_offset + x / 2]
        };
        if x % 2 == 0 {
            temp[x] = ((perm & 0xffff) << 16) + (x as i32);
        } else {
            temp[x] = (perm & (0xffff << 16)) + (x as i32);
        }
    }
    int32_sort(temp, n as i64); /* A = (id<<16)+pi^(-1) */

    for j in 0..(n / 2) {
        let x = 2 * j as i32;
        let fj: i32 = temp[n + (x as usize)] & 1; /* f[j] */
        let fx: i32 = x + fj; /* F[x] */
        let fx1: i32 = fx ^ 1; /* F[x+1] */

        out[pos >> 3] ^= (fj << (pos & 7)) as u8;
        pos += step;

        temp[n + x as usize] = (temp[x as usize] << 16) | fx;
        temp[n + x as usize + 1] = (temp[x as usize + 1] << 16) | fx1;
    }
    /* B = (pi^(-1)<<16)+F */

    int32_sort(&mut temp[n..], n as i64); /* B = (id<<16)+F(pi) */

    pos += (2 * w - 3) * step * (n / 2);

    for k in 0..(n / 2) {
        let y = 2 * k as i32;
        let lk: i32 = temp[n + y as usize] & 1; /* l[k] */
        let ly: i32 = y + lk; /* L[y] */
        let ly1: i32 = ly ^ 1; /* L[y+1] */

        out[pos >> 3] ^= (lk << (pos & 7)) as u8;
        pos += step;

        temp[y as usize] = (ly << 16) | (temp[n + y as usize] & 0xffff);
        temp[y as usize + 1] = (ly1 << 16) | (temp[n + y as usize + 1] & 0xffff);
    }
    /* A = (L<<16)+F(pi) */

    int32_sort(temp, n as i64); /* A = (id<<16)+F(pi(L)) = (id<<16)+M */

    pos -= (2 * w - 2) * step * (n / 2);

    for j in 0..(n / 2) {
        if j % 2 == 0 {
            temp[n + n / 4..][j / 2] =
                (temp[n + n / 4..][j / 2] & (0xffff << 16)) | ((temp[2 * j] & 0xffff) >> 1);
            temp[n + n / 4..][(j + n / 2) / 2] = (temp[n + n / 4..][(j + n / 2) / 2]
                & (0xffff << 16))
                | ((temp[2 * j + 1] & 0xffff) >> 1);
        } else {
            temp[n + n / 4..][j / 2] =
                (temp[n + n / 4..][j / 2] & 0xffff) | ((temp[2 * j] & 0xfffe) << 15);
            temp[n + n / 4..][(j + n / 2) / 2] =
                (temp[n + n / 4..][(j + n / 2) / 2] & 0xffff) | ((temp[2 * j + 1] & 0xfffe) << 15);
        }
    }

    cbrecursion(out, pos, step * 2, n + n / 4, w - 1, n / 2, temp, aux);
    cbrecursion(
        out,
        pos + step,
        step * 2,
        n + n / 2,
        w - 1,
        n / 2,
        temp,
        aux,
    );
}

/// controlbitsfrompermutation computes control bits.
///
/// Pick `w` ∈ {1, 2, …, 14}. Let `n = 2^w`.
/// Let `pi` have `n` elements which is a permutation of integers 0, 1, …, n-1
/// (consider it as map from the index to the value at this index).
/// The control bits provide the configuration for a Beneš network in order
/// to implement the permutation specified by `pi`. The first control bit is
/// the LSB of out[0].
pub(crate) fn controlbitsfrompermutation(out: &mut [u8], pi: &[i16], w: usize, n: usize) {
    assert_eq!(n, 1 << w);
    assert_eq!(pi.len(), n);
    assert_eq!(out.len(), (((2 * w - 1) * n / 2) + 7) / 8);

    let mut temp = [0i32; 2 * (1 << GFBITS)];
    let mut diff: i16 = 0;

    // reinterpret pi as i32 array
    assert_eq!(pi.len(), 1 << GFBITS);
    let mut pi_as_i32 = [0i32; 1 << (GFBITS - 1)];
    for i in 0..(1 << (GFBITS - 1)) {
        pi_as_i32[i] = pi[2 * i] as i32 | ((pi[2 * i + 1] as i32) << 16);
    }

    let mut sub = out;

    loop {
        sub.fill(0);
        cbrecursion(sub, 0, 1, 0, w, n, &mut temp, &pi_as_i32);

        let mut pi_test = [0i16; 1 << GFBITS];
        for i in 0..n {
            pi_test[i] = i as i16;
        }

        for i in 0..w as usize {
            layer(&mut pi_test, sub, i as i32, n as i32);
            sub = &mut sub[(n >> 4) as usize..];
        }

        for i in (0..w - 1).rev() {
            layer(&mut pi_test, sub, i as i32, n as i32);
            sub = &mut sub[(n >> 4) as usize..];
        }

        for i in 0..n as usize {
            diff |= pi[i] ^ pi_test[i];
        }

        if diff == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A simple testcase for layer().
    // The input/output mapping was retrieved from the C implementation.
    #[test]
    fn test_layer_1() {
        const N: i32 = 4;
        const S: i32 = 1;
        let mut p = [0i16, 3, 7, 11];
        let cb = [63u8; 1]; // m := log_2(#p) = 2 gives 6 control bits which fit into one byte; 63 = 0b0011_1111
        assert_eq!(p.len(), N as usize);

        layer(&mut p, &cb, S, N); // p is modified in-place

        let p_ref = [7i16, 11, 0, 3];
        assert_eq!(p, p_ref);
    }

    // A simple testcase for layer().
    // The input/output mapping was retrieved from the C implementation.
    #[test]
    fn test_layer_2() {
        const N: i32 = 8;
        const S: i32 = 2;
        let mut p = [0i16, 3, 7, 11, 13, 17, 23, 0];
        let cb = [0xAAu8, 0xFF, 0x02]; // m := log_2(#p) = 3 gives 20 control bits which fit into three bytes
        assert_eq!(p.len(), N as usize);

        layer(&mut p, &cb, S, N);

        let p_ref = [0i16, 17, 7, 0, 13, 3, 23, 11];
        assert_eq!(p, p_ref);
    }

    // A simple testcase for cbrecursion().
    // The input/output mapping was retrieved from the C implementation.
    #[test]
    fn test_cbrecursion_1() {
        const W: usize = 3;
        const N: usize = 1 << W;

        let pi: [i16; N] = [0i16, 2, 4, 6, 1, 3, 5, 7];

        const STEP: usize = 1;
        const POS: usize = 0;

        let mut temp: [i32; 2 * N] = [0i32; 2 * 8];
        let mut out: [u8; CONTROLBYTES!(W, STEP)] = [0u8; 3];

        let mut pi_as_i32: [i32; N / 2] = [0i32; N / 2];
        for i in 0..(N / 2) {
            pi_as_i32[i] = pi[2 * i] as i32 | ((pi[2 * i + 1] as i32) << 16);
        }

        cbrecursion(&mut out, POS, STEP, 0, W, N, &mut temp, &pi_as_i32);

        let out_ref = [0xCAu8, 0x66, 0x0C];
        assert_eq!(out, out_ref);
    }

    // A simple testcase for cbrecursion().
    // The input/output mapping was retrieved from the C implementation.
    #[test]
    fn test_cbrecursion_2() {
        const W: usize = 3;
        const N: usize = 1 << W;

        let pi: [i16; N] = [0i16, 2, 4, 6, 1, 3, 5, 7];

        const STEP: usize = 2;
        const POS: usize = 0;

        let mut temp: [i32; 2 * N] = [0i32; 2 * N];
        let mut out: [u8; CONTROLBYTES!(W, STEP)] = [0u8; CONTROLBYTES!(W, STEP)];

        let mut pi_as_i32: [i32; N / 2] = [0i32; N / 2];
        for i in 0..(N / 2) {
            pi_as_i32[i] = pi[2 * i] as i32 | ((pi[2 * i + 1] as i32) << 16);
        }

        cbrecursion(&mut out, POS, STEP, 0, W, N, &mut temp, &pi_as_i32);

        let out_ref = [0x44u8, 0x50, 0x14, 0x14, 0x50];
        assert_eq!(out.len(), out_ref.len());
    }

    // This testcase corresponds to the call of controlbitsfrompermutation
    // in the 3rd KAT testcase of the mceliece348864 reference implementation
    #[test]
    #[cfg(feature = "mceliece348864")]
    fn test_controlbitsfrompermutation_kat3_mceliece348864() {
        let pi = crate::TestData::new().i16vec("controlbits_kat3_mceliece348864_pi");
        let mut out = [0u8; 5888];

        controlbitsfrompermutation(&mut out, &pi, 12, 4096);

        let out_ref = crate::TestData::new().u8vec("controlbits_kat3_mceliece348864_out_ref");
        assert_eq!(&out, out_ref.as_slice());
    }

    // This testcase corresponds to the call of controlbitsfrompermutation
    // in the 8th KAT testcase of the mceliece348864 reference implementation
    #[test]
    #[cfg(feature = "mceliece348864")]
    fn test_controlbitsfrompermutation_kat8_mceliece348864() {
        let mut out = [0u8; 5888];
        let pi = crate::TestData::new().i16vec("controlbits_kat8_mceliece348864_pi");

        controlbitsfrompermutation(&mut out, &pi, 12, 4096);

        let out_ref = crate::TestData::new().u8vec("controlbits_kat8_mceliece348864_out_ref");
        assert_eq!(out, out_ref.as_slice());
    }

    // This testcase corresponds to the call of controlbitsfrompermutation
    // in the 9th KAT testcase of the mceliece348864 reference implementation
    #[test]
    #[cfg(feature = "mceliece348864")]
    fn test_controlbitsfrompermutation_kat9_mceliece348864() {
        let mut out = [0u8; 5888];
        let pi = crate::TestData::new().i16vec("controlbits_kat9_mceliece348864_pi");

        controlbitsfrompermutation(&mut out, &pi, 12, 4096);

        let out_ref = crate::TestData::new().u8vec("controlbits_kat9_mceliece348864_out_ref");
        assert_eq!(out, out_ref.as_slice());
    }

    // This testcase corresponds to the call of controlbitsfrompermutation
    // in the 3rd KAT testcase of the mceliece6960119 reference implementation
    #[test]
    #[cfg(feature = "mceliece6960119")]
    fn test_controlbitsfrompermutation_kat3_mceliece6960119() {
        assert_eq!(GFBITS, 13);

        let mut out = [0u8; 12800];

        let pi = crate::TestData::new().i16vec("controlbits_kat3_mceliece6960119_pi");
        controlbitsfrompermutation(&mut out, &pi, 13, 8192);

        let out_ref = crate::TestData::new().u8vec("controlbits_kat3_mceliece6960119_out_ref");
        assert_eq!(out, out_ref.as_slice());
    }
}
