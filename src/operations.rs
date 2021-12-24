use std::mem::size_of;

use crate::{
    crypto_hash::shake256,
    decrypt,
    decrypt::decrypt,
    encrypt::encrypt,
    params::{COND_BYTES, GFBITS, IRR_BYTES, SYND_BYTES, SYS_N, SYS_T},
    randombytes::randombytes,
    sk_gen::genpoly_gen,
    util::{load_gf, store_gf},
};

pub fn crypto_kem_enc(c: &mut [u8], key: &mut [u8], pk: &mut [u8]) -> i32 {
    let mut two_e = [0u8; 1 + SYS_N / 8];
    two_e[0] = 2;

    let mut one_ec = [0u8; 1 + SYS_N / 8 + (SYND_BYTES + 32)];
    one_ec[0] = 1;

    encrypt(c, pk, &mut two_e[1..]);

    shake256(&mut c[SYND_BYTES..], &two_e);

    for i in 1..SYS_N / 8 {
        one_ec[i] = two_e[i];
    }

    for i in 1 + SYS_N / 8..SYND_BYTES + 32 {
        one_ec[i] = c[i];
    }

    shake256(key, &one_ec);

    return 0;
}

pub fn crypto_kem_dec(key: &mut [u8], c: &mut [u8], sk: &mut [u8]) -> i32 {
    let mut ret_confirm: u8 = 0;
    let mut ret_decrypt: u8 = 0;

    let mut m: u16 = 0;

    let mut conf = [0u8; 32];
    let mut two_e = [0u8; 1 + SYS_N / 8];
    two_e[0] = 2;

    let mut preimage = [0u8; 1 + SYS_N / 8 + (SYND_BYTES + 32)];

    ret_decrypt = decrypt(&mut two_e[1..], &mut sk[40..], c);

    shake256(&mut conf, &two_e);

    for i in 0..32 {
        ret_confirm |= conf[i] ^ c[SYND_BYTES + i];
    }

    m = (ret_decrypt | ret_confirm) as u16;
    m = m.wrapping_sub(1);
    m >>= 8;

    let mut index = 0;
    preimage[index] = (m & 1) as u8;
    index += 1;

    let mut s = &mut sk[40 + IRR_BYTES + COND_BYTES..];

    for i in 0..SYS_N / 8 {
        preimage[index] = (!m as u8 & s[i]) | (m as u8 & two_e[i + 1]);
        index += 1;
    }

    for i in 0..SYND_BYTES + 32 {
        preimage[index] = c[i];
        index += 1;
    }

    shake256(key, &preimage);

    /*println!("KEY: ");
    for i in 0..32 {
        println!("{}", key[i]);
    }
    println!("ENDK");*/

    return 0;
}

pub fn crypto_kem_keypair(pk: &mut [u8], mut sk: &mut [u8]) -> i32 {
    let mut seed = [0u8; 33];
    seed[0] = 64;
    // ------------------ 1024     +     32768      +  256   +  32
    let mut r = [0u8; SYS_N / 8 + (1 << GFBITS) * 4 + SYS_T * 2 + 32];
    let mut pivots: u64 = 0;

    let mut f = [0u16; SYS_T];
    let mut irr = [0u16; SYS_T];

    let mut perm = [0u32; 1 << GFBITS];
    let mut pi = [0u16; 1 << GFBITS];

    match randombytes(&mut seed[1..], 32) {
        Err(e) => {
            println!("{:?}", e);
        }
        Ok(()) => {}
    }

    loop {
        // expanding and updating the seed
        shake256(&mut r, &seed[0..33]);
        // memcpy loop
        for i in 0..32 {
            sk[i] = seed[i + 1];
        }

        sk = &mut sk[32 + 8..];

        for i in 0..32 {
            //seed[i+1] =
        }

        let mut i = 0;
        for chunk in r.chunks_mut((i + 1) * 2) {
            f[i] = load_gf(chunk);
            i += 1;
            if i == SYS_T {
                break;
            }
        }

        if genpoly_gen(&mut irr, &mut f) != 0 {
            continue;
        }
        i = 0;
        for chunk in sk.chunks_mut((i + 1) * 2) {
            store_gf(chunk, irr[i]);
            i += 1;
            if i == SYS_T {
                break;
            }
        }
    }

    return 0;
}

#[test]
pub fn test_crypto_kem_dec() {
    use crate::{
        api::{CRYPTO_CIPHERTEXTBYTES, CRYPTO_SECRETKEYBYTES},
        decrypt_arrays::{C_INPUT, SK_INPUT},
    };

    let mut sk = SK_INPUT.to_vec();
    assert_eq!(sk.len(), CRYPTO_SECRETKEYBYTES + 40);

    let mut c = C_INPUT.to_vec();
    assert_eq!(c.len(), CRYPTO_CIPHERTEXTBYTES);

    let mut test_key = [0u8; 32];

    let compare_key: [u8; 32] = [
        236, 53, 216, 229, 94, 183, 172, 233, 134, 102, 148, 252, 9, 21, 64, 46, 160, 114, 10, 133,
        197, 163, 219, 138, 147, 214, 39, 240, 67, 42, 69, 46,
    ];

    crypto_kem_dec(&mut test_key, &mut c, &mut sk);

    assert_eq!(test_key, compare_key);
}

#[test]
pub fn test_crypto_kem_enc() {}