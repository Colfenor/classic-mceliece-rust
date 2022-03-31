use std::error;
use std::fmt;
use std::io::Read;

use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake256;

#[derive(Debug)]
struct ShakeIOError(String);

impl error::Error for ShakeIOError {}

impl fmt::Display for ShakeIOError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "shake failed to read data: {}", self.0)
    }
}

/// Utilizes the SHAKE256 hash function. Input and output is of arbitrary length.
pub(crate) fn shake256(output: &mut [u8], input: &[u8]) -> Result<(), Box<dyn error::Error>> {
    let mut shake_hash_fn = Shake256::default();
    shake_hash_fn.update(input);

    let mut result_shake = shake_hash_fn.finalize_xof();
    match result_shake.read(output) {
        Ok(_) => Ok(()),
        Err(e) => Err(Box::new(ShakeIOError(e.to_string()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error;

    #[test]
    fn test_shake256() -> Result<(), Box<dyn error::Error>> {
        let compare_array = crate::TestData::new().u8vec("shake256_digest_expected");

        let mut c = [0u8; 448];
        let mut two_e = [0u8; 1025];
        two_e[0] = 2;

        shake256(&mut c[208..=239], &two_e[0..1025])?;
        assert_eq!(&c, compare_array.as_slice());

        Ok(())
    }
}
