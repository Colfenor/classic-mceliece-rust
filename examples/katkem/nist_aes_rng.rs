//! Implementation of a pseudo-random number generator
//! based on AES256 in CTR mode.
//!
//! The implementation follows the design discussed in this blogpost:
//! <https://lukas-prokop.at/articles/2021-12-31-nists-rng-in-rust>

use aes::BlockEncrypt;
use aes::NewBlockCipher;
use rand::CryptoRng;
use rand::RngCore;
use std::fmt;

/// AesState is a struct storing data of a pseudo-random number generator.
/// Using `randombytes_init`, it can be initialized once. Using the `RngCore` interface,
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

    /// Initialize/reset the state based on the seed provided as `entropy_input`
    pub fn randombytes_init(&mut self, entropy_input: [u8; 48]) {
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

impl RngCore for AesState {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(16) {
            let count = u128::from_be_bytes(self.v);
            self.v.copy_from_slice(&(count + 1).to_be_bytes());

            let mut block = [0u8; 16];
            Self::aes256_ecb(&self.key, &self.v, &mut block);

            (*chunk).copy_from_slice(&block[..chunk.len()]);
        }

        Self::aes256_ctr_update(&mut None, &mut self.key, &mut self.v);
        self.reseed_counter += 1;
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for AesState {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;

    const RNG_REF1 : &'static str= "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA19810F5392D076276EF41277C3AB6E94A4E3B7DCC104A05BB089D338BF55C72CAB375389A94BB920BD5D6DC9E7F2EC6FDE028B6F5724BB039F3652AD98DF8CE6C97013210B84BBE81388C3D141D61957C73BCDC5E5CD92525F46A2B757B03CAB5C337004A2DA35324A325713564DAE28F57ACC6DBE32A0726190BAA6B8A0A255AA1AD01E8DD569AA36D096256C420718A69D46D8DB1C6DD40606A0BE3C235BEFE623A90593F82D6A8F9F924E44E36BE87F7D26B8445966F9EE329C426C12521E85F6FD4ECD5D566BA0A3487125D79CC64";
    const RNG_REF2 : &'static str= "C17E034061ED5EA817C41D61636281E816F817DCF753A91D97C018FF82FBC9B1728FC66AF114B57978FB6082B70D285140B26725AA5F7BB4409820F67E2D656EDACA30B5BB12EB5249CC3809B188CF0CC95B5AE0EFE8FC5887152CB6601B4CCF9FC411894FA0C0264EB51A481D4D7074FDF065053030C8A92BFCDD06BF18C8489C38D03784FD63001830E5A385A4A37866693F5BDAB8A8A25B519DDBF2D28268601D95BEED647E430484A227C023B0297A282F06C91376433BDE5EC3ABBA8C06B830C26452EA2FA7EDEA8DCFE20EAFCF8980B3D5AECEF89DD861ACEC1F5F7CD2AE6B3CDE3C1D80A2830DD0B9E8468AFAD161981074BEB33DF1CDFF9A5214F9F0";

    #[test]
    fn test_rng_rand_interface() {
        let mut data = [0u8; 256];
        let mut entropy_input = [0u8; 48];
        let mut personalization_string = [0u8; 48];
        let mut rng_state = AesState::new();

        for i in 0..48 {
            entropy_input[i] = i as u8;
            personalization_string[i] = 0 as u8;
        }

        rng_state.randombytes_init(entropy_input);

        rng_state.fill_bytes(&mut data);
        let ref1_src = hex::decode(RNG_REF1).unwrap();
        let ref1 = <[u8; 256]>::try_from(ref1_src).unwrap();
        assert_eq!(data, ref1);

        rng_state.fill_bytes(&mut data);
        let ref2_src = hex::decode(RNG_REF2).unwrap();
        let ref2 = <[u8; 256]>::try_from(ref2_src).unwrap();
        assert_eq!(data, ref2);
    }
}
