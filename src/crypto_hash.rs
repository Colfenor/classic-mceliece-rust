//! Hash function implementations (only SHAKE)

use sha3::digest::ExtendableOutput;
use sha3::Shake256;

/// Utilizes the SHAKE256 hash function. Input and output is of arbitrary length.
#[inline]
pub(crate) fn shake256(output: &mut [u8], input: &[u8]) {
    Shake256::digest_xof(input, output);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestData;

    #[test]
    fn test_shake256() {
        let compare_array = TestData::new().u8vec("shake256_digest_expected");

        let mut c = [0u8; 448];
        let mut two_e = [0u8; 1025];
        two_e[0] = 2;

        shake256(&mut c[208..=239], &two_e[0..1025]);
        assert_eq!(&c, compare_array.as_slice());
    }
}
