use aes::Aes256;
use block_modes::block_padding::NoPadding;
use block_modes::{BlockMode, Ecb};
use lazy_static::lazy_static;
use std::error;
use std::sync;

//by @prokls

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

struct Aes256CtrDrbgStruct {
    key: [u8; 32],
    v: [u8; 16],
    reseed_counter: i32,
}

pub fn randombytes(x: &mut [u8], mut xlen: usize) -> Result<(), Box<dyn error::Error>> {
    let mut block = [0u8; 16];
    let mut i: usize = 0;

    while xlen > 0 {
        for j in (0..16).rev() {
            if DRBG_CTX.lock()?.v[j] == 0xff {
                DRBG_CTX.lock()?.v[j] = 0;
            } else {
                DRBG_CTX.lock()?.v[j] += 1;
                break;
            }
        }

        {
            let r = &DRBG_CTX.lock()?;
            aes256_ecb(&r.key[..], &r.v[..], &mut block)?;
        }

        if xlen > 15 {
            x[i..i + 16].copy_from_slice(&block);
            i += 16;
            xlen -= 16;
        } else {
            x[i..(i + xlen as usize)].copy_from_slice(&block[0..xlen as usize]);
            xlen = 0;
        }
    }
    aes256_ctr_drbg_update(&[])?;
    DRBG_CTX.lock()?.reseed_counter += 1;
    Ok(())
}

pub fn randombytes_init(entropy_input: [u8; 48]) -> Result<(), Box<dyn error::Error>> {
    DRBG_CTX.lock()?.key = [0u8; 32];
    DRBG_CTX.lock()?.v = [0u8; 16];

    aes256_ctr_drbg_update(&entropy_input)?;
    DRBG_CTX.lock()?.reseed_counter = 1;
    Ok(())
}

fn aes256_ecb(key: &[u8], ctr: &[u8], buffer: &mut [u8]) -> Result<(), Box<dyn error::Error>> {
    let cipher = Ecb::<Aes256, NoPadding>::new_from_slices(key, Default::default())?;
    let pos = ctr.len();
    buffer[..pos].copy_from_slice(ctr);
    cipher.encrypt(buffer, pos)?;
    Ok(())
}

fn aes256_ctr_drbg_update(provided_data: &[u8]) -> Result<(), Box<dyn error::Error>> {
    let mut temp = [0u8; 48];
    for i in 0..3 {
        for j in (0..16).rev() {
            if DRBG_CTX.lock()?.v[j] == 0xff {
                DRBG_CTX.lock()?.v[j] = 0;
            } else {
                DRBG_CTX.lock()?.v[j] += 1;
                break;
            }
        }
        let mut tmp_key = [0u8; 32];
        tmp_key.copy_from_slice(&DRBG_CTX.lock().unwrap().key[..]);
        aes256_ecb(
            &tmp_key,
            &DRBG_CTX.lock()?.v,
            &mut temp[(16 * i)..(16 * (i + 1))],
        )?;
    }

    if !provided_data.is_empty() {
        for i in 0..48 {
            temp[i] ^= provided_data[i];
        }
    }

    DRBG_CTX.lock()?.key.copy_from_slice(&temp[0..32]);
    DRBG_CTX.lock()?.v.copy_from_slice(&temp[32..48]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_randombytes() -> Result<(), Box<dyn error::Error>> {
        let mut entropy_input = [0u8; 48];

        for i in 0..48u8 {
            entropy_input[i as usize] = i;
        }

        randombytes_init(entropy_input)?;

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
