/*
  This file is for loading/storing data in a little-endian fashion
*/

pub fn store_gf(dest: &mut char, a: Gf) {
    dest[0] = a & 0xFF;
	dest[1] = a >> 8;
}

// function parameters are immutable 
// by default in rust, rust u8 == unsigned char in c
pub fn load_gf(src: &[u8]) -> u16 {
    let a: u16;

    a = src[1];
	a <<= 8;
	a |= src[0];

    a & GFMASK
}

pub fn load4(input: &[u8]) -> u32 {
    let mut ret: u32 = input[3];

    let i = 2;
    while (i >= 0) {
        ret <<= 8;
		ret |= input[i];

        i = i - 1;
    }
    ret
}

pub fn store8(out: &[u8], input: u64) {
    out[0] = (input >> 0x00) & 0xFF;
	out[1] = (input >> 0x08) & 0xFF;
	out[2] = (input >> 0x10) & 0xFF;
	out[3] = (input >> 0x18) & 0xFF;
	out[4] = (input >> 0x20) & 0xFF;
	out[5] = (input >> 0x28) & 0xFF;
	out[6] = (input >> 0x30) & 0xFF;
	out[7] = (input >> 0x38) & 0xFF;
}

pub fn load8(input: &[u8]) -> u64 {
    let mut ret: u32 = input[7];

    let i = 6;
    while (i >= 0) {
        ret <<= 8;
		ret |= input[i];

        i = i - 1;
    }
    ret
}

pub fn bitrev(a: Gf) -> Gf {
	a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
	a = ((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4);
	a = ((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2);
	a = ((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1);

    a >> 3
}

