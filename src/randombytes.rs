//! Implementation of a pseudo-random number generator
//! based on AES256 in CTR mode.
//!
//! The implementation follows the design discussed in this blogpost:
//! <https://lukas-prokop.at/articles/2021-12-31-nists-rng-in-rust>

use aes::BlockEncrypt;
use aes::NewBlockCipher;
use std::error;
use std::fmt;

/// Trait requiring primitives to generate pseudo-random numbers.
/// `AesState` is an object implementing this trait.
pub trait RNGState {
    /// Fill the buffer `x` with pseudo-random bytes resulting from the
    /// RNG run updating the RNG state
    fn randombytes(&mut self, x: &mut [u8]) -> Result<(), Box<dyn error::Error>>;
    /// Initialize/reset the RNG state based on the seed provided as `entropy_input`
    fn randombytes_init(&mut self, entropy_input: [u8; 48]);
}

/// AesState is a struct storing data of a pseudo-random number generator.
/// Using `randombytes_init`, it can be initialized once. Using `randombytes`,
/// one can successively fetch new pseudo-random numbers.
#[derive(Clone, Debug, PartialEq)]
pub struct AesState {
    pub key: [u8; 32],
    pub v: [u8; 16],
    pub reseed_counter: i32,
}

impl AesState {
    /// Returns a fresh RNG state
    pub fn new() -> AesState {
        AesState {
            key: [0; 32],
            v: [0; 16],
            reseed_counter: 0,
        }
    }

    /// This runs AES256 in ECB mode. Here `key` is a 256-bit AES key,
    /// `ctr` is a 128-bit plaintext value and `buffer` is a 128-bit
    /// ciphertext value.
    fn aes256_ecb(key: &[u8; 32], ctr: &[u8; 16], buffer: &mut [u8; 16]) {
        let cipher = aes::Aes256::new(key.into());
        buffer.copy_from_slice(ctr);
        cipher.encrypt_block(buffer.into());
    }

    /// Update `key` and `v` with `provided_data` by running one round of AES in counter mode
    fn aes256_ctr_update(
        provided_data: &mut Option<[u8; 48]>,
        key: &mut [u8; 32],
        v: &mut [u8; 16],
    ) {
        let mut temp = [[0u8; 16]; 3];

        for tmp in &mut temp[0..3] {
            let count = u128::from_be_bytes(*v);
            v.copy_from_slice(&(count + 1).to_be_bytes());

            Self::aes256_ecb(key, v, tmp);
        }

        if let Some(d) = provided_data {
            for j in 0..3 {
                for i in 0..16 {
                    temp[j][i] ^= d[16 * j + i];
                }
            }
        }

        key[0..16].copy_from_slice(&temp[0]);
        key[16..32].copy_from_slice(&temp[1]);
        v.copy_from_slice(&temp[2]);
    }
}

impl RNGState for AesState {
    /// Fill the buffer `x` with pseudo-random bytes resulting from the
    /// AES run in counter mode updating the object state
    fn randombytes(&mut self, x: &mut [u8]) -> Result<(), Box<dyn error::Error>> {
        for chunk in x.chunks_mut(16) {
            let count = u128::from_be_bytes(self.v);
            self.v.copy_from_slice(&(count + 1).to_be_bytes());

            let mut block = [0u8; 16];
            Self::aes256_ecb(&self.key, &self.v, &mut block);

            (*chunk).copy_from_slice(&block[..chunk.len()]);
        }

        Self::aes256_ctr_update(&mut None, &mut self.key, &mut self.v);
        self.reseed_counter += 1;

        Ok(())
    }

    /// Initialize/reset the state based on the seed provided as `entropy_input`
    fn randombytes_init(&mut self, entropy_input: [u8; 48]) {
        self.key = [0u8; 32];
        self.v = [0u8; 16];
        self.reseed_counter = 1i32;

        Self::aes256_ctr_update(&mut Some(entropy_input), &mut self.key, &mut self.v);
        self.reseed_counter = 1;
    }
}

impl Default for AesState {
    fn default() -> Self {
        Self::new()
    }
}

impl Eq for AesState {}

impl fmt::Display for AesState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "AesState {{")?;
        writeln!(f, "  key = {:?}", self.key)?;
        writeln!(f, "  v   = {:?}", self.v)?;
        writeln!(f, "  reseed_counter = {}", self.reseed_counter)?;
        writeln!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;

    #[test]
    fn test_rng() -> Result<(), Box<dyn error::Error>> {
        let mut data = [0u8; 256];
        let mut entropy_input = [0u8; 48];
        let mut personalization_string = [0u8; 48];
        let mut rng_state = AesState::new();

        for i in 0..48 {
            entropy_input[i] = i as u8;
            personalization_string[i] = 0 as u8;
        }

        rng_state.randombytes_init(entropy_input);

        rng_state.randombytes(&mut data)?;
        let ref1_src = crate::TestData::new().u8vec("rng_ref1");
        let ref1 = <[u8; 256]>::try_from(ref1_src).unwrap();
        assert_eq!(data, ref1);

        rng_state.randombytes(&mut data)?;
        let ref2_src = crate::TestData::new().u8vec("rng_ref2");
        let ref2 = <[u8; 256]>::try_from(ref2_src).unwrap();
        assert_eq!(data, ref2);

        Ok(())
    }
}
