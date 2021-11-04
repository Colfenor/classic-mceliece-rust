use crate::gf::{Gf, GFMASK};
/*
  This file is for loading/storing data in a little-endian fashion
*/

pub fn store_gf(dest: &mut [u8], a: Gf) {
    dest[0] = (a as u8) & 0xFF;
    dest[1] = (a as u8) >> 8;
}

// function parameters are immutable
// by default in rust, rust u8 == unsigned char in c
pub fn load_gf(src: &[u8]) -> u16 {
    let mut a: u16;

    a = src[1] as u16;
    a <<= 8;
    a |= src[0] as u16;

    a & (GFMASK as u16)
}

pub fn load4(input: &[u8]) -> u32 {
    let mut ret: u32 = input[3] as u32;

    for i in (0..=2).rev() {
        ret <<= 8;
        ret |= input[i] as u32;
    }
    ret
}

pub fn store8(out: &mut [u8], input: u64) {
    out[0] = input.overflowing_shr(0x00).0 as u8 & 0xFF;
    out[1] = input.overflowing_shr(0x08).0 as u8 & 0xFF;
    out[2] = input.overflowing_shr(0x10).0 as u8 & 0xFF;
    out[3] = input.overflowing_shr(0x18).0 as u8 & 0xFF;
    out[4] = input.overflowing_shr(0x20).0 as u8 & 0xFF;
    out[5] = input.overflowing_shr(0x28).0 as u8 & 0xFF;
    out[6] = input.overflowing_shr(0x30).0 as u8 & 0xFF;
    out[7] = input.overflowing_shr(0x38).0 as u8 & 0xFF;
}

pub fn load8(input: &[u8]) -> u64 {
    let mut ret: u64 = input[7] as u64;

    for i in (0..=6).rev() {
        ret <<= 8;
        ret |= input[i] as u64;
    }

    ret
}

pub fn bitrev(mut a: Gf) -> Gf {
    a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
    a = ((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4);
    a = ((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2);
    a = ((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1);

    a >> 3
}
