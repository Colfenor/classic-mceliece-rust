

// Definitions
type Gf = u16;
const GFBITS: usize = 13;
const GFMASK: usize = (1 << GFBITS) - 1;

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