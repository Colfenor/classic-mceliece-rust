// Definitions
type Gf = u16;
const GFBITS: usize = 13;
const GFMASK: usize = (1 << GFBITS) - 1;
const SYS_T: usize = 128;

pub fn gf_iszero(a: Gf) -> Gf {
    let mut t: u32 = a as u32;

    t -= 1;
    t >>= 19;

    t as Gf
}

// 0 .. 65.535
// binary addition mod 2^1 is eq. to the XOR operation
pub fn gf_add(in0: Gf, in1: Gf) -> Gf {
    in0 ^ in1
}

pub fn gf_mul(in0: Gf, in1: Gf) -> Gf {
    let (mut tmp, t0, t1, mut t): (u64, u64, u64, u64);

    t0 = in0 as u64;
    t1 = in1 as u64;

    tmp = t0 * (t1 & 1); // if LSB 0, tmp will be 0, otherwise value of t0

    // (t1 & (1 << i)) -> is either t1 ^ i or zero
    for i in 1..GFBITS {
        tmp ^= t0 * (t1 & (1 << i));
    }
    // actually a multiplication tmp = t0 * t1 ...

    // multiplication in a polynomial ring
    // example of polynom multiplication,
    // (x^2 + 1) * (x + 2)
    // polynom division

    t = tmp & 0x1FF0000;
    tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

    t = tmp & 0x000E000;
    tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

    (tmp & GFMASK as u64) as u16
}

/* input: field element in */
/* return: (in^2)^2 */
#[inline]
pub fn gf_sq2(input: Gf) -> Gf {
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

/* input: field element in, m */
/* return: (in^2)*m */
#[inline]
pub fn gf_sqmul(input: Gf, m: Gf) -> Gf {
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

/* input: field element in, m */
/* return: ((in^2)^2)*m */
#[inline]
pub fn gf_sq2mul(input: Gf, m: Gf) -> Gf {
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

/* input: field element den, num */
/* return: (num/den) */
pub fn gf_frac(den: Gf, num: Gf) -> Gf {
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

pub fn gf_inv(den: Gf) -> Gf {
    gf_frac(den, 1 as Gf)
}

/* input: in0, in1 in GF((2^m)^t)*/
/* output: out = in0*in1 */
pub fn GF_mul(out: &mut [Gf; SYS_T], in0: &mut [Gf; SYS_T], in1: &mut [Gf; SYS_T]) {
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
