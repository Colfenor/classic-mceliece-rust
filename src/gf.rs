

// Definitions
type Gf = u16;
const GFBITS: u16 = 13;
const GFMASK: u16 = (1 << GFBITS) - 1;

pub fn gf_iszero(a: Gf) -> Gf {
    
    let mut t: u32 = a as u32;

    t -= 1;
    t >>= 19;

    t as Gf
}

pub fn gf_add(in0: Gf, in1: Gf) -> Gf {
	in0 ^ in1
}

pub fn gf_mul(in0: Gf, in1: Gf) -> Gf {

    let (mut tmp, mut t0, mut t1, mut t): (u64, u64, u64, u64);

    t0 = in0 as u64;
    t1 = in1 as u64;

    tmp = t0 * (t1 & 1);

    for i in 1..GFBITS {
        tmp ^= t0 * (t1 & (1 << i));
    }

    t = tmp & 0x1FF0000;
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

	t = tmp & 0x000E000;
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

    (tmp & GFMASK as u64) as u16
}