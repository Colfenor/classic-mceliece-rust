//! Hash function implementations (only SHAKE)

use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake256;

/// Utilizes the SHAKE256 hash function. Input and output is of arbitrary length.
pub(crate) fn shake256(output: &mut [u8], input: &[u8]) {
    let mut shake_hash_fn = Shake256::default();
    shake_hash_fn.update(input);
    shake_hash_fn.finalize_xof_into(output);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shake256() {
        let compare_array = crate::TestData::new().u8vec("shake256_digest_expected");

        let mut c = [0u8; 448];
        let mut two_e = [0u8; 1025];
        two_e[0] = 2;

        shake256(&mut c[208..=239], &two_e[0..1025]);
        assert_eq!(&c, compare_array.as_slice());
    }
}
