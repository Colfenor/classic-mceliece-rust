//! Module to implement Galois field operations

use super::{GFBITS, GFMASK, SYS_T};
pub(crate) type Gf = u16;

/// Store Gf element `a` in array `dest`
pub(crate) fn store_gf(dest: &mut [u8; 2], a: Gf) {
    dest[0] = (a & 0xFF) as u8;
    dest[1] = a.overflowing_shr(8).0 as u8;
}

/// Interpret 2 bytes from `src` as integer and return it as Gf element
pub(crate) fn load_gf(src: &[u8; 2]) -> Gf {
    let mut a: u16 = src[1] as u16;
    a <<= 8;
    a |= src[0] as u16;

    a & (GFMASK as u16)
}

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

    tmp as u16 & GFMASK as u16
}

/// Computes the square `in0^2` for Gf element `in0`
#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
fn gf_sq(in0: Gf) -> Gf {
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

    x as u16 & GFMASK as u16
}

/// Computes the division `num/den` for Gf elements `den` and `num`
#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
pub(crate) fn gf_frac(den: Gf, num: Gf) -> Gf {
    gf_mul(gf_inv(den), num)
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

/// Multiply Gf elements `in0` and `in0` in GF((2^m)^t) and store result in `out`.
/// Called `GF_mul` in the C implementation.
pub(crate) fn gf_mul_inplace(out: &mut [Gf; SYS_T], in0: &[Gf; SYS_T], in1: &[Gf; SYS_T]) {
    let mut prod: [Gf; SYS_T * 2 - 1] = [0; SYS_T * 2 - 1];

    for i in 0..SYS_T {
        for j in 0..SYS_T {
            prod[i + j] ^= gf_mul(in0[i], in1[j]);
        }
    }

    for i in (SYS_T..=(SYS_T - 1) * 2).rev() {
        prod[i - SYS_T + 3] ^= prod[i];
        prod[i - SYS_T + 1] ^= prod[i];
        prod[i - SYS_T] ^= gf_mul(prod[i], 2);
    }

    out[0..SYS_T].copy_from_slice(&prod[0..SYS_T]);
}

/// Reverse the bits of Gf element `a`. The LSB becomes the MSB.
/// The 2nd LSB becomes the 2nd MSB. etc …
pub(crate) fn bitrev(mut a: Gf) -> Gf {
    a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
    a = ((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4);
    a = ((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2);
    a = ((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1);

    #[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
    {
        a >> 4
    }
    #[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
    {
        a >> 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Unit tests

    #[test]
    fn test_load_gf() {
        assert_eq!(load_gf(&[0xAB, 0x42]), 0x02AB);
    }

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

    #[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
    #[test]
    fn test_gf_mul() {
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
        assert_eq!(gf_mul(125, 19), 1879);
        assert_eq!(gf_mul(19, 125), 1879);
        assert_eq!(gf_mul(125, 37), 3625);
        assert_eq!(gf_mul(37, 125), 3625);
        assert_eq!(gf_mul(4095, 1), 4095);
        assert_eq!(gf_mul(1, 4095), 4095);
        assert_eq!(gf_mul(8191, 1), 4086);
        assert_eq!(gf_mul(1, 8191), 4095);
    }

    #[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
    #[test]
    fn test_gf_sq() {
        assert_eq!(gf_sq(0), 0);
        assert_eq!(gf_sq(1), 1);
        assert_eq!(gf_sq(2), 4);
        assert_eq!(gf_sq(3), 5);
        assert_eq!(gf_sq(4), 16);
        assert_eq!(gf_sq(4095), 2746);
        assert_eq!(gf_sq(4096), 0);
        assert_eq!(gf_sq(8191), 2746);
        assert_eq!(gf_sq(8192), 0);
        assert_eq!(gf_sq(0xFFFF), 2746);
    }

    #[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
    #[test]
    fn test_gf_frac() {
        assert_eq!(gf_frac(1, 6733), 2637);
        assert_eq!(gf_frac(2, 0), 0);
        assert_eq!(gf_frac(2, 4), 2);
        assert_eq!(gf_frac(2, 4096), 0);
        assert_eq!(gf_frac(3, 9), 7);
        assert_eq!(gf_frac(5, 4591), 99);
        assert_eq!(gf_frac(550, 10), 3344);
        assert_eq!(gf_frac(5501, 3), 1763);
    }

    #[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
    #[test]
    fn test_gf_inv() {
        assert_eq!(gf_inv(0), 0);
        assert_eq!(gf_inv(1), 1);
        assert_eq!(gf_inv(2), 2052);
        assert_eq!(gf_inv(3), 4088);
        assert_eq!(gf_inv(4), 1026);
        assert_eq!(gf_inv(4095), 1539);
        assert_eq!(gf_inv(4096), 0);
        assert_eq!(gf_inv(8191), 1539);
        assert_eq!(gf_inv(8192), 0);
        assert_eq!(gf_inv(0xFFFF), 1539);
    }

    #[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
    #[test]
    fn test_gf_mul_inplace() {
        let mut res = [0u16; SYS_T];
        let mut arg1 = [0u16; SYS_T];
        let mut arg2 = [0u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                1u16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [0u16; SYS_T];
        arg2 = [1u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                1u16, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [1u16; SYS_T];
        arg2 = [0u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                1u16, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [0u16; SYS_T];
        arg2 = [5u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                1u16, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
                5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
                5, 5, 5, 5, 5, 5, 5, 5, 5
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [5u16; SYS_T];
        arg2 = [0u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                1u16, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
                5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
                5, 5, 5, 5, 5, 5, 5, 5, 5
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [0u16; SYS_T];
        arg2 = [1024u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                1u16, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
                1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
                1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
                1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
                1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [1024u16; SYS_T];
        arg2 = [0u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                1u16, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
                1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
                1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
                1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
                1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [2u16; SYS_T];
        arg2 = [6u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                25u16, 16, 28, 4, 28, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4,
                16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4,
                16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [6u16; SYS_T];
        arg2 = [2u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                25u16, 16, 28, 4, 28, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4,
                16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4,
                16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4, 16, 4
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [3u16; SYS_T];
        arg2 = [8u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                49u16, 35, 59, 11, 59, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11,
                35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35,
                11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11,
                35, 11
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [8u16; SYS_T];
        arg2 = [3u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                49u16, 35, 59, 11, 59, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11,
                35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35,
                11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11, 35, 11,
                35, 11
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [125u16; SYS_T];
        arg2 = [19u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                3759u16, 2455, 3776, 110, 3776, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110,
                2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455,
                110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110,
                2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455,
                110, 2455, 110, 2455, 110
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [19u16; SYS_T];
        arg2 = [125u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                3759u16, 2455, 3776, 110, 3776, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110,
                2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455,
                110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110,
                2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455, 110, 2455,
                110, 2455, 110, 2455, 110
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [125u16; SYS_T];
        arg2 = [37u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                3162u16, 554, 3075, 88, 3075, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554,
                88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554,
                88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554,
                88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [37u16; SYS_T];
        arg2 = [125u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                3162u16, 554, 3075, 88, 3075, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554,
                88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554,
                88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88, 554,
                88, 554, 88, 554, 88, 554, 88, 554, 88, 554, 88
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [4095u16; SYS_T];
        arg2 = [1u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                4086u16, 4086, 9, 4094, 9, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094,
                4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094,
                4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094,
                4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094,
                4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [1u16; SYS_T];
        arg2 = [4095u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                4086u16, 4086, 9, 4094, 9, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094,
                4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094,
                4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094,
                4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094,
                4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [8191u16; SYS_T];
        arg2 = [1u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                4068u16, 4068, 18, 4087, 18, 4087, 4068, 4087, 4068, 4087, 4068, 4087, 4068, 4087,
                4068, 4087, 4068, 4087, 4068, 4087, 4068, 4087, 4068, 4087, 4068, 4087, 4068, 4087,
                4068, 4087, 4068, 4087, 4068, 4087, 4068, 4087, 4068, 4087, 4068, 4087, 4068, 4087,
                4068, 4087, 4068, 4087, 4068, 4087, 4068, 4087, 4068, 4087, 4068, 4087, 4068, 4087,
                4068, 4087, 4068, 4087, 4068, 4087, 4068, 4087
            ]
        );
        res = [0u16; SYS_T];
        arg1 = [1u16; SYS_T];
        arg2 = [8191u16; SYS_T];
        arg1[0] = 1;
        arg2[0] = 1;
        gf_mul_inplace(&mut res, &arg1, &arg2);
        assert_eq!(
            res,
            [
                4086u16, 4086, 9, 4094, 9, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094,
                4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094,
                4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094,
                4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094,
                4086, 4094, 4086, 4094, 4086, 4094, 4086, 4094
            ]
        );
    }

    #[test]
    fn test_bitrev() {
        assert_eq!(bitrev(0b1011_0111_0111_1011), 0b0000_1101_1110_1110);
        assert_eq!(bitrev(0b0110_1010_0101_1011), 0b0000_1101_1010_0101);
    }
}
