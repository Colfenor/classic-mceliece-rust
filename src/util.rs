//! This file is for loading/storing data in a little-endian fashion and a `bitrev` function

use crate::{gf::Gf, params::GFMASK};

/// Store Gf element `a` in array `dest`
pub(crate) fn store_gf(dest: &mut [u8; 2], a: Gf) {
    dest[0] = (a & 0xFF) as u8;
    dest[1] = a.overflowing_shr(8).0 as u8;
}

/// Interpret 2 bytes from `src` as integer and return it as Gf element
pub(crate) fn load_gf(src: &[u8; 2]) -> Gf {
    let mut a: u16;

    a = src[1] as u16;
    a <<= 8;
    a |= src[0] as u16;

    a & (GFMASK as u16)
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

    #[test]
    fn test_load_gf() {
        assert_eq!(load_gf(&[0xAB, 0x42]), 0x02AB);
    }

    #[test]
    #[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
    fn test_bitrev() {
        assert_eq!(bitrev(0b1011_0111_0111_1011), 0b0000_1101_1110_1110);
        assert_eq!(bitrev(0b0110_1010_0101_1011), 0b0000_1101_1010_0101);
    }

    #[test]
    #[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
    fn test_bitrev() {
        assert_eq!(bitrev(0b1011_0111_0111_1011), 0b0001_1011_1101_1101);
        assert_eq!(bitrev(0b0110_1010_0101_1011), 0b0001_1011_0100_1010);
    }
}
