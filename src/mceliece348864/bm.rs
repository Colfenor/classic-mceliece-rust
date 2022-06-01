//! This file implements the Berlekamp-Massey algorithm
//! see <http://crypto.stanford.edu/~mironov/cs359/massey.pdf>

use super::gf::{gf_frac, gf_mul, Gf};
use super::SYS_T;

fn min(a: usize, b: usize) -> usize {
    let c = (a < b) as isize;
    let d = c << (isize::BITS - 1);
    let e = (d >> (isize::BITS - 1)) as usize;
    (a & e) | (b & !e)
}

/// The Berlekamp-Massey algorithm.
/// Uses `s` as input (sequence of field elements)
/// and `out` as output (minimal polynomial of `s`)
pub(crate) fn bm(out: &mut [Gf; SYS_T + 1], s: &mut [Gf; 2 * SYS_T]) {
    let mut l: u16 = 0;
    let mut mle: u16;
    let mut mne: u16;

    let mut t = [0u16; SYS_T + 1];
    let mut c = [0u16; SYS_T + 1];
    let mut b = [0u16; SYS_T + 1];

    let mut base: Gf = 1;

    b[1] = 1;
    c[0] = 1;

    for n in 0..(2 * SYS_T) {
        let mut d: Gf = 0;
        for i in 0..=min(n, SYS_T) {
            d ^= gf_mul(c[i], s[n - i]);
        }
        mne = d;
        mne = mne.wrapping_sub(1);
        mne >>= 15;
        mne = mne.wrapping_sub(1);

        mle = n as u16;
        mle = mle.wrapping_sub(l.wrapping_mul(2));
        mle >>= 15;
        mle = mle.wrapping_sub(1);
        mle &= mne;

        for i in 0..=SYS_T {
            t[i] = c[i];
        }

        let f: Gf = gf_frac(base, d);

        for i in 0..=SYS_T {
            c[i] ^= gf_mul(f, b[i]) & mne;
        }

        l = (l & !mle) | ((n as u16 + 1 - l) & mle);

        for i in 0..=SYS_T {
            b[i] = (b[i] & !mle) | (t[i] & mle);
        }

        base = (base & !mle) | (d & mle);

        for i in (1..=SYS_T).rev() {
            b[i] = b[i - 1];
        }

        b[0] = 0;
    }

    for i in 0..=SYS_T {
        out[i] = c[SYS_T - i];
    }
}

#[cfg(test)]
#[cfg(feature = "mceliece8192128f")]
mod tests {
    use super::*;
    use crate::macros::sub;

    #[test]
    fn test_simple_bm() {
        assert_eq!(SYS_T + 1, 129);

        let compare_array: [u16; 129] = [
            7438, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 3333, 1794, 2310, 1794, 5390, 1794,
            2310, 1794, 7432, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 3333, 1794, 2310, 1794,
            5390, 1794, 2310, 1794, 7433, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 3333, 1794,
            2310, 1794, 5390, 1794, 2310, 1794, 7432, 1794, 2310, 1794, 5390, 1794, 2310, 1794,
            3333, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 7435, 1794, 2310, 1794, 5390, 1794,
            2310, 1794, 3333, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 7432, 1794, 2310, 1794,
            5390, 1794, 2310, 1794, 3333, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 7433, 1794,
            2310, 1794, 5390, 1794, 2310, 1794, 3333, 1794, 2310, 1794, 5390, 1794, 2310, 1794,
            7432, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 3333, 1794, 2310, 1794, 5390, 1794,
            2310, 1794, 1,
        ];

        let mut locator = [0u16; SYS_T + 1];
        let mut s = [0u16; SYS_T * 2];

        for i in 0..s.len() {
            s[i] = i as u16;
        }

        bm(&mut locator, &mut s);

        assert_eq!(locator, compare_array);
    }

    #[test]
    fn test_first_round_bm() {
        let compare_array =
            crate::TestData::new().u16vec("mceliece8192128f_bm_first_round_compare_array");
        let compare_array_slice = sub!(compare_array.as_slice(), 0, SYS_T + 1, u16);
        let mut s_input = crate::TestData::new().u16vec("mceliece8192128f_bm_first_round_s_input");
        let s_input_slice = sub!(mut s_input.as_mut_slice(), 0, 2 * SYS_T, u16);

        let mut locator = [0u16; SYS_T + 1];
        bm(&mut locator, s_input_slice);

        assert_eq!(&locator, compare_array_slice);
    }
}
