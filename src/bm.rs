use crate::gf::{gf_frac, gf_mul, Gf, SYS_T};

/*
  This file is for the Berlekamp-Massey algorithm
  see http://crypto.stanford.edu/~mironov/cs359/massey.pdf
*/

// TODO verify side channel sec
pub fn min(a: usize, b: usize) -> usize {
    if a < b {
        a
    } else {
        b
    }
}

/* the Berlekamp-Massey algorithm */
/* input: s, sequence of field elements */
/* output: out, minimal polynomial of s */

// out 129, s 256
pub fn bm(out: &mut [Gf; SYS_T + 1], s: &mut [Gf; 256]) {
    //let N: u64 = 0;
    let mut L: u16 = 0;
    let mut mle: u16;
    let mut mne: u16;

    let mut T = [0u16; SYS_T + 1];
    let mut C = [0u16; SYS_T + 1];
    let mut B = [0u16; SYS_T + 1];

    let mut b: Gf = 1;
    let mut d: Gf;
    let mut f: Gf;

    for i in 0..SYS_T + 1 {
        C[i] = 0;
        B[i] = 0;
    }

    B[1] = 1;
    C[0] = 1;

    for N in 0..(2 * SYS_T) {
        d = 0;
        //println!("ROUND N: {}", N);
        for i in 0..=min(N, SYS_T) {
            d ^= gf_mul(C[i], s[N - i]);
            //println!("mul:{} C:{} s:{} i:{} N:{}", gf_mul(C[i], s[ N-i]), C[i], s[ N-i], i, N);
        }
        mne = d;
        mne = mne.wrapping_sub(1);
        mne >>= 15;
        mne = mne.wrapping_sub(1);

        mle = N as u16;
        mle = mle.wrapping_sub(2 * L);
        mle >>= 15;
        mle = mle.wrapping_sub(1);
        mle &= mne;

        for i in 0..=SYS_T {
            T[i] = C[i];
        }

        f = gf_frac(b, d);

        for i in 0..=SYS_T {
            C[i] ^= gf_mul(f, B[i]) & mne;
        }

        L = (L & !mle) | ((N as u16 + 1 - L) & mle);

        for i in 0..=SYS_T {
            B[i] = (B[i] & !mle) | (T[i] & mle);
        }

        b = (b & !mle) | (d & mle);

        let mut i = SYS_T;
        while i >= 1 {
            B[i] = B[i - 1];

            i -= 1;
        }

        B[0] = 0;
    }

    for i in 0..=SYS_T {
        out[i] = C[SYS_T - i];
    }
}

#[test]
fn test_bm() {
    let compare_array: [u16; SYS_T + 1] = [
        7438, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 3333, 1794, 2310, 1794, 5390, 1794, 2310,
        1794, 7432, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 3333, 1794, 2310, 1794, 5390, 1794,
        2310, 1794, 7433, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 3333, 1794, 2310, 1794, 5390,
        1794, 2310, 1794, 7432, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 3333, 1794, 2310, 1794,
        5390, 1794, 2310, 1794, 7435, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 3333, 1794, 2310,
        1794, 5390, 1794, 2310, 1794, 7432, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 3333, 1794,
        2310, 1794, 5390, 1794, 2310, 1794, 7433, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 3333,
        1794, 2310, 1794, 5390, 1794, 2310, 1794, 7432, 1794, 2310, 1794, 5390, 1794, 2310, 1794,
        3333, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 1,
    ];

    let mut locator = [0u16; SYS_T + 1];
    let mut s = [0u16; SYS_T * 2];

    for i in 0..s.len() {
        s[i] = i as u16;
    }

    bm(&mut locator, &mut s);

    /*for i in 0..locator.len() {
        println!("i:{} loc:{}", i, locator[i]);
    }*/

    assert_eq!(locator, compare_array);
}
