//! This file is for loading/storing data in a little-endian fashion

use crate::{gf::Gf, params::GFMASK};

// Store Gf element `a` in array `dest`
pub fn store_gf(dest: &mut [u8], a: Gf) {
    dest[0] = (a & 0xFF) as u8;
    dest[1] = a.overflowing_shr(8).0 as u8;
}

/// Interpret 2 bytes from `src` as integer and return it as Gf element
pub fn load_gf(src: &[u8]) -> Gf {
    let mut a: u16;

    a = src[1] as u16;
    a <<= 8;
    a |= src[0] as u16;

    a & (GFMASK as u16)
}

/// Interpret 4 bytes from `src` as integer and return it as u32
pub fn load4(input: &[u8]) -> u32 {
    let mut ret: u32 = input[3] as u32;

    for i in (0..=2).rev() {
        ret <<= 8;
        ret |= input[i] as u32;
    }
    ret
}

/// Take `input` and store it in 8 bytes, `out` points to.
pub fn store8(out: &mut [u8], input: u64) {
    out[0] = input.wrapping_shr(0x00) as u8;
    out[1] = input.wrapping_shr(0x08) as u8;
    out[2] = input.wrapping_shr(0x10) as u8;
    out[3] = input.wrapping_shr(0x18) as u8;
    out[4] = input.wrapping_shr(0x20) as u8;
    out[5] = input.wrapping_shr(0x28) as u8;
    out[6] = input.wrapping_shr(0x30) as u8;
    out[7] = input.wrapping_shr(0x38) as u8;
}

/// Interpret 8 bytes from `input` as integer and return it as u64.
pub fn load8(input: &[u8]) -> u64 {
    let mut ret: u64 = input[7] as u64;

    for i in (0..=6).rev() {
        ret <<= 8;
        ret |= input[i] as u64;
    }

    ret
}

/// Reverse the bits of Gf element `a`. The LSB becomes the MSB.
/// The 2nd LSB becomes the 2nd MSB. etc …
pub fn bitrev(mut a: Gf) -> Gf {
    a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
    a = ((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4);
    a = ((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2);
    a = ((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1);

    a >> 3
}
