//! Module to implement Galois field operations

use crate::params::{GFBITS, GFMASK, SYS_T};
pub(crate) type Gf = u16;

#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
const GFBITMASK: u64 = ((1 << GFBITS) - 1) as u64;

/// Does Gf element `a` have value 0? Returns yes (8191 = `u16::MAX/8`) or no (0) as Gf element.
pub(crate) fn gf_iszero(a: Gf) -> Gf {
    let mut t = (a as u32).wrapping_sub(1u32);
    t >>= 19;
    t as u16
}

/// Add Gf elements stored bitwise in `in0` and `in1`. Thus, the LSB of `in0` is added to the LSB of `in1` w.r.t. Gf(2).
/// This continues for all 16 bits. Since addition in Gf(2) corresponds to a XOR operation, the implementation uses a
/// simple XOR instruction.
pub(crate) fn gf_add(in0: Gf, in1: Gf) -> Gf {
    in0 ^ in1
}

/// Multiplication of two Gf elements.
#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
pub(crate) fn gf_mul(in0: Gf, in1: Gf) -> Gf {
    let (mut tmp, t0, t1, mut t): (u64, u64, u64, u64);

    t0 = in0 as u64;
    t1 = in1 as u64;

    tmp = t0 * (t1 & 1); // if LSB 0, tmp will be 0, otherwise value of t0

    // (t1 & (1 << i)) ⇒ is either t1 to the power of i or zero
    for i in 1..GFBITS {
        tmp ^= t0 * (t1 & (1 << i));
    }

    // polynomial reduction
    t = tmp & 0x7FC000;
	tmp ^= t >> 9;
	tmp ^= t >> 12;

	t = tmp & 0x3000;
	tmp ^= t >> 9;
	tmp ^= t >> 12;

	(tmp & GFBITMASK) as u16
}

/// Multiplication of two Gf elements.
#[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
pub(crate) fn gf_mul(in0: Gf, in1: Gf) -> Gf {
    let t0: u64 = in0 as u64;
    let t1: u64 = in1 as u64;
    let mut tmp: u64 = t0 * (t1 & 1); // if LSB 0, tmp will be 0, otherwise value of t0

    // (t1 & (1 << i)) ∈ {0, t1 ^ i}
    for i in 1..GFBITS {
        // implements the convolution, thus the actual multiplication
        tmp ^= t0 * (t1 & (1 << i));
    }

    // polynomial reduction according to the field polynomial
    let mut t: u64 = tmp & 0x1FF0000;
    tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

    t = tmp & 0x000E000;
    tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

    tmp as u16 & GFMASK as u16
}

#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
pub(crate) fn gf_sq(in0: Gf) -> Gf {
	let b = [0x55555555u32, 0x33333333, 0x0F0F0F0F, 0x00FF00FF];

	let mut x: u32 = in0 as u32; 
	x = (x | (x << 8)) & b[3];
	x = (x | (x << 4)) & b[2];
	x = (x | (x << 2)) & b[1];
	x = (x | (x << 1)) & b[0];

	let mut t = x & 0x7FC000;
	x ^= t >> 9;
	x ^= t >> 12;

	t = x & 0x3000;
	x ^= t >> 9;
	x ^= t >> 12;

	x as u16 & GFBITMASK as u16
}


/// Computes the double-square `(input^2)^2` for Gf element `input`
#[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
#[inline]
fn gf_sq2(input: Gf) -> Gf {
    const B: [u64; 4] = [
        0x1111111111111111,
        0x0303030303030303,
        0x000F000F000F000F,
        0x000000FF000000FF,
    ];

    const M: [u64; 4] = [
        0x0001FF0000000000,
        0x000000FF80000000,
        0x000000007FC00000,
        0x00000000003FE000,
    ];

    let mut x: u64 = input as u64;
    let mut t: u64;

    x = (x | (x << 24)) & B[3];
    x = (x | (x << 12)) & B[2];
    x = (x | (x << 6)) & B[1];
    x = (x | (x << 3)) & B[0];

    for i in 0..4 {
        t = x & M[i];
        x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
    }

    (x & GFMASK as u64) as u16
}

/// Computes the square `input^2` multiplied by `m` for Gf elements `input` and `m`. Thus `(input^2)*m`.
#[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
#[inline]
fn gf_sqmul(input: Gf, m: Gf) -> Gf {
    let mut x: u64;
    let mut t0: u64;
    let t1: u64;
    let mut t: u64;

    const M: [u64; 3] = [0x0000001FF0000000, 0x000000000FF80000, 0x000000000007E000];

    t0 = input as u64;
    t1 = m as u64;

    x = (t1 << 6) * (t0 & (1 << 6));

    t0 ^= t0 << 7;

    x ^= t1 * (t0 & (0x04001));
    x ^= (t1 * (t0 & (0x08002))) << 1;
    x ^= (t1 * (t0 & (0x10004))) << 2;
    x ^= (t1 * (t0 & (0x20008))) << 3;
    x ^= (t1 * (t0 & (0x40010))) << 4;
    x ^= (t1 * (t0 & (0x80020))) << 5;

    for i in 0..3 {
        t = x & M[i];
        x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
    }

    (x & GFMASK as u64) as u16
}

/// Computes the double-square `(input^2)^2` multiplied by `m`
/// for Gf elements `input` and `m`. Thus `((in^2)^2)*m`.
#[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
#[inline]
fn gf_sq2mul(input: Gf, m: Gf) -> Gf {
    let mut x: u64;
    let mut t0: u64;
    let t1: u64;
    let mut t: u64;

    const M: [u64; 6] = [
        0x1FF0000000000000,
        0x000FF80000000000,
        0x000007FC00000000,
        0x00000003FE000000,
        0x0000000001FE0000,
        0x000000000001E000,
    ];

    t0 = input as u64;
    t1 = m as u64;

    x = (t1 << 18) * (t0 & (1 << 6));

    t0 ^= t0 << 21;

    x ^= t1 * (t0 & (0x010000001));
    x ^= (t1 * (t0 & (0x020000002))) << 3;
    x ^= (t1 * (t0 & (0x040000004))) << 6;
    x ^= (t1 * (t0 & (0x080000008))) << 9;
    x ^= (t1 * (t0 & (0x100000010))) << 12;
    x ^= (t1 * (t0 & (0x200000020))) << 15;

    for i in 0..6 {
        t = x & M[i];
        x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
    }

    (x & GFMASK as u64) as u16
}

/// Computes the division `num/den` for Gf elements `den` and `num`
#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
pub(crate) fn gf_frac(den: Gf, num: Gf) -> Gf {
	gf_mul(gf_inv(den), num)
}


/// Computes the division `num/den` for Gf elements `den` and `num`
#[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
pub(crate) fn gf_frac(den: Gf, num: Gf) -> Gf {
    let tmp_11: Gf;
    let tmp_1111: Gf;
    let mut out: Gf;

    tmp_11 = gf_sqmul(den, den); // ^11
    tmp_1111 = gf_sq2mul(tmp_11, tmp_11); // ^1111
    out = gf_sq2(tmp_1111);
    out = gf_sq2mul(out, tmp_1111); // ^11111111
    out = gf_sq2(out);
    out = gf_sq2mul(out, tmp_1111); // ^111111111111

    gf_sqmul(out, num) // ^1111111111110 = ^-1
}

/// Computes the inverse element of `den` in the Galois field.
#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
pub(crate) fn gf_inv(in0: Gf) -> Gf {
	let mut out = gf_sq(in0);
	let tmp_11 = gf_mul(out, in0); // 11

	out = gf_sq(tmp_11);
	out = gf_sq(out);
	let tmp_1111 = gf_mul(out, tmp_11); // 1111

	out = gf_sq(tmp_1111);
	out = gf_sq(out);
	out = gf_sq(out);
	out = gf_sq(out);
	out = gf_mul(out, tmp_1111); // 11111111

	out = gf_sq(out);
	out = gf_sq(out);
	out = gf_mul(out, tmp_11); // 1111111111

	out = gf_sq(out);
	out = gf_mul(out, in0); // 11111111111

	gf_sq(out) // 111111111110
}

/// Computes the inverse element of `den` in the Galois field.
#[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
pub(crate) fn gf_inv(den: Gf) -> Gf {
    gf_frac(den, 1 as Gf)
}
/// Multiply Gf elements `in0` and `in0` in GF((2^m)^t) and store result in `out`.
#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
pub(crate) fn GF_mul(out: &mut [Gf; SYS_T], in0: &[Gf; SYS_T], in1: &[Gf; SYS_T]) {
    let mut prod: [Gf; SYS_T * 2 - 1] = [0; SYS_T * 2 - 1];

    for i in 0..SYS_T {
        for j in 0..SYS_T {
            prod[i + j] ^= gf_mul(in0[i], in1[j]);
        }
    }

    let mut i = (SYS_T - 1) * 2;

    while i >= SYS_T {
        prod[i - SYS_T + 3] ^= prod[i];
        prod[i - SYS_T + 1] ^= prod[i];
        prod[i - SYS_T + 0] ^= prod[i];

        i -= 1;
    }

    for i in 0..SYS_T {
        out[i] = prod[i];
    }
}

/// Multiply Gf elements `in0` and `in0` in GF((2^m)^t) and store result in `out`.
#[cfg(any(feature = "mceliece460896", feature = "mceliece460896f"))]
pub(crate) fn GF_mul(out: &mut [Gf; SYS_T], in0: &[Gf; SYS_T], in1: &[Gf; SYS_T]) {
    let mut prod: [Gf; SYS_T * 2 - 1] = [0; SYS_T * 2 - 1];

    for i in 0..SYS_T {
        for j in 0..SYS_T {
            prod[i + j] ^= gf_mul(in0[i], in1[j]);
        }
    }

    let mut i = (SYS_T - 1) * 2;

    while i >= SYS_T {
        prod[i - SYS_T + 10] ^= prod[i];
        prod[i - SYS_T + 9] ^= prod[i];
        prod[i - SYS_T + 6] ^= prod[i];
        prod[i - SYS_T + 0] ^= prod[i];

        i -= 1;
    }

    for i in 0..SYS_T {
        out[i] = prod[i];
    }
}

/// Multiply Gf elements `in0` and `in0` in GF((2^m)^t) and store result in `out`.
#[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
pub(crate) fn GF_mul(out: &mut [Gf; SYS_T], in0: &[Gf; SYS_T], in1: &[Gf; SYS_T]) {
    let mut prod: [Gf; SYS_T * 2 - 1] = [0; SYS_T * 2 - 1];

    for i in 0..SYS_T {
        for j in 0..SYS_T {
            prod[i + j] ^= gf_mul(in0[i], in1[j]);
        }
    }

    let mut i = (SYS_T - 1) * 2;

    while i >= SYS_T {
        prod[i - SYS_T + 8] ^= prod[i];
        prod[i - SYS_T + 0] ^= prod[i];

        i -= 1;
    }

    for i in 0..SYS_T {
        out[i] = prod[i];
    }
}

/// Multiply Gf elements `in0` and `in0` in GF((2^m)^t) and store result in `out`.
#[cfg(any(feature = "mceliece6688128", feature = "mceliece6688128f", feature = "mceliece8192128", feature = "mceliece8192128f"))]
pub(crate) fn GF_mul(out: &mut [Gf; SYS_T], in0: &[Gf; SYS_T], in1: &[Gf; SYS_T]) {
    let mut prod: [Gf; SYS_T * 2 - 1] = [0; SYS_T * 2 - 1];

    for i in 0..SYS_T {
        for j in 0..SYS_T {
            prod[i + j] ^= gf_mul(in0[i], in1[j]);
        }
    }

    let mut i = (SYS_T - 1) * 2;

    while i >= SYS_T {
        prod[i - SYS_T + 7] ^= prod[i];
        prod[i - SYS_T + 2] ^= prod[i];
        prod[i - SYS_T + 1] ^= prod[i];
        prod[i - SYS_T + 0] ^= prod[i];

        i -= 1;
    }

    for i in 0..SYS_T {
        out[i] = prod[i];
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // Unit tests
    #[test]
    fn test_gf_iszero() {
        const YES: u16 = 8191;
        const NO: u16 = 0;

        assert_eq!(gf_iszero(0), YES);
        assert_eq!(gf_iszero(1), NO);
        assert_eq!(gf_iszero(2), NO);
        assert_eq!(gf_iszero(3), NO);
        assert_eq!(gf_iszero(1024), NO);
        assert_eq!(gf_iszero(1025), NO);
        assert_eq!(gf_iszero(65535), NO);
    }

    #[test]
    fn test_gf_add() {
        assert_eq!(gf_add(0x0000, 0x0000), 0x0000);
        assert_eq!(gf_add(0x0000, 0x0001), 0x0001);
        assert_eq!(gf_add(0x0001, 0x0000), 0x0001);
        assert_eq!(gf_add(0x0001, 0x0001), 0x0000);
        assert_eq!(gf_add(0x000F, 0x0000), 0x000F);
        assert_eq!(gf_add(0x000F, 0x0001), 0x000E); // 0b1111 + 0b0001 = 0b1110
        assert_eq!(gf_add(0x00FF, 0x0100), 0x01FF);
        assert_eq!(gf_add(0xF0F0, 0x0F0F), 0xFFFF);
    }

    #[test]
    fn test_gf_mul() {
        assert_eq!(gf_mul(0, 0), 0);
        assert_eq!(gf_mul(0, 0), 0);
        assert_eq!(gf_mul(0, 1), 0);
        assert_eq!(gf_mul(1, 0), 0);
        assert_eq!(gf_mul(0, 5), 0);
        assert_eq!(gf_mul(5, 0), 0);
        assert_eq!(gf_mul(0, 1024), 0);
        assert_eq!(gf_mul(1024, 0), 0);
        assert_eq!(gf_mul(2, 6), 12);
        assert_eq!(gf_mul(6, 2), 12);
        assert_eq!(gf_mul(3, 8), 24);
        assert_eq!(gf_mul(8, 3), 24);
        assert_eq!(gf_mul(2, 6), 12);
        assert_eq!(gf_mul(2, 6), 12);
    }

    #[test]
    fn test_gf_sq2() {
        let mut result_var = gf_sq2(2);
        assert_eq!(result_var, 16);

        result_var = gf_sq2(3);
        assert_eq!(result_var, 17);

        result_var = gf_sq2(0);
        assert_eq!(result_var, 0);
    }

    #[test]
    fn test_gf_sqmul() {
        let mut result_var = gf_sqmul(2, 2);
        assert_eq!(result_var, 8);

        result_var = gf_sqmul(2, 3);
        assert_eq!(result_var, 12);

        result_var = gf_sqmul(3, 2);
        assert_eq!(result_var, 10);

        result_var = gf_sqmul(0, 2);
        assert_eq!(result_var, 0);

        result_var = gf_sqmul(2, 0);
        assert_eq!(result_var, 0);
    }

    #[test]
    fn test_gf_sq2mul() {
        let mut result_var = gf_sq2mul(2, 2);
        assert_eq!(result_var, 32);

        result_var = gf_sq2mul(2, 3);
        assert_eq!(result_var, 48);

        result_var = gf_sq2mul(3, 2);
        assert_eq!(result_var, 34);

        result_var = gf_sq2mul(4, 2);
        assert_eq!(result_var, 512);

        result_var = gf_sq2mul(5, 2);
        assert_eq!(result_var, 514);

        result_var = gf_sq2mul(5, 0);
        assert_eq!(result_var, 0);

        result_var = gf_sq2mul(0, 5);
        assert_eq!(result_var, 0);
    }

    #[test]
    fn test_gf_frac() {
        let mut result_var = gf_frac(0, 2);
        assert_eq!(result_var, 0);

        result_var = gf_frac(1, 5);
        assert_eq!(result_var, 5);

        result_var = gf_frac(2, 1);
        assert_eq!(result_var, 4109);
    }

    #[test]
    fn test_gf_inv() {
        let mut result_var = gf_inv(0);
        assert_eq!(result_var, 0);

        result_var = gf_inv(1);
        assert_eq!(result_var, 1);

        result_var = gf_inv(2);
        assert_eq!(result_var, 4109);

        result_var = gf_inv(5);
        assert_eq!(result_var, 5467);
    }
}
