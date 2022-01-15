use aes::BlockEncrypt;
use aes::NewBlockCipher;
use hex;
use lazy_static::lazy_static;
use std::error;
use std::sync;

//by @prokls

pub struct Aes256CtrDrbgStruct {
    pub key: [u8; 32],
    pub v: [u8; 16],
    pub reseed_counter: i32,
}
// global variable holding the RNG state
lazy_static! {
    static ref DRBG_CTX: sync::Mutex<Aes256CtrDrbgStruct> = sync::Mutex::new({
        Aes256CtrDrbgStruct {
            key: [0u8; 32],
            v: [0u8; 16],
            reseed_counter: 0,
        }
    });
}

fn aes256_ecb(key: &[u8; 32], ctr: &[u8; 16], buffer: &mut [u8; 16]) {
    let cipher = aes::Aes256::new(key.into());
    buffer.copy_from_slice(ctr);
    cipher.encrypt_block(buffer.into());
}

fn aes256_ctr_drbg_update(
    provided_data: &mut Option<[u8; 48]>,
    key: &mut [u8; 32],
    v: &mut [u8; 16],
) {
    let mut temp = [[0u8; 16]; 3];

    for i in 0..3 {
        let count = u128::from_be_bytes(*v);
        v.copy_from_slice(&(count + 1).to_be_bytes());

        aes256_ecb(key, v, &mut temp[i]);
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

pub fn randombytes_init(
    entropy_input: &[u8; 48],
    personalization_string: &[u8; 48],
    _security_strength: u32,
) -> Result<(), Box<dyn error::Error>> {
    let mut drbg_ctx = DRBG_CTX.lock()?;

    // reset ctx
    drbg_ctx.key = [0u8; 32];
    drbg_ctx.v = [0u8; 16];
    drbg_ctx.reseed_counter = 1i32;

    // get seed ready
    let mut seed = [0u8; 48];
    for i in 0..48 {
        seed[i] = entropy_input[i] ^ personalization_string[i];
    }

    let mut key = drbg_ctx.key;
    aes256_ctr_drbg_update(&mut Some(seed), &mut key, &mut drbg_ctx.v);
    drbg_ctx.key.copy_from_slice(&key);

    Ok(())
}

pub fn randombytes(x: &mut [u8], xlen: usize) -> Result<(), Box<dyn error::Error>> {
    assert_eq!(x.len(), xlen);
    let mut drbg_ctx = DRBG_CTX.lock()?;

    for chunk in x.chunks_mut(16) {
        let count = u128::from_be_bytes(drbg_ctx.v);
        drbg_ctx.v.copy_from_slice(&(count + 1).to_be_bytes());

        let mut block = [0u8; 16];
        aes256_ecb(&drbg_ctx.key, &drbg_ctx.v, &mut block);

        (*chunk).copy_from_slice(&mut block);
    }

    let mut key = drbg_ctx.key;
    aes256_ctr_drbg_update(&mut None, &mut key, &mut drbg_ctx.v);
    drbg_ctx.key.copy_from_slice(&key);

    drbg_ctx.reseed_counter += 1;
    println!("reseedctr:{}", drbg_ctx.reseed_counter);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_randombytes() -> Result<(), Box<dyn error::Error>> {
        let mut entropy_input = [0u8; 48];
        let mut personalization_string = [0u8; 48];

        for i in 0..48u8 {
            entropy_input[i as usize] = i;
        }

        randombytes_init(&entropy_input, &personalization_string, 256)?;

        let mut given1 = [0u8; 48];
        randombytes(&mut given1, 48)?;

        let mut given2 = [0u8; 48];
        randombytes(&mut given2, 48)?;

        let expected_output1 = [
            0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF,
            0x7A, 0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC,
            0x9A, 0xBC, 0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85,
            0x41, 0xDB, 0xD2, 0xE1, 0xFF, 0xA1,
        ];
        let expected_output2 = [
            0xD8, 0x1C, 0x4D, 0x8D, 0x73, 0x4F, 0xCB, 0xFB, 0xEA, 0xDE, 0x3D, 0x3F, 0x8A, 0x03,
            0x9F, 0xAA, 0x2A, 0x2C, 0x99, 0x57, 0xE8, 0x35, 0xAD, 0x55, 0xB2, 0x2E, 0x75, 0xBF,
            0x57, 0xBB, 0x55, 0x6A, 0xC8, 0x1A, 0xDD, 0xE6, 0xAE, 0xEB, 0x4A, 0x5A, 0x87, 0x5C,
            0x3B, 0xFC, 0xAD, 0xFA, 0x95, 0x8F,
        ];

        assert_eq!(given1, expected_output1);
        assert_eq!(given2, expected_output2);

        Ok(())
    }
}
