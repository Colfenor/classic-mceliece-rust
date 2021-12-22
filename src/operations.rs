use crate::{
    crypto_hash::shake256,
    decrypt,
    decrypt::decrypt,
    encrypt::encrypt,
    params::{COND_BYTES, IRR_BYTES, SYND_BYTES, SYS_N},
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

    /*
    WORKS :)
    println!("pre: ");
    for i in 0..1 + SYS_N/8 + (SYND_BYTES + 32) {
        println!("{}", preimage[i]);
    }
    println!("ENDI");*/

    shake256(key, &preimage);

    return 0;
}

pub fn crypto_kem_keypair(pk: &mut [u8], sk: &mut [u8]) -> i32 {
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

    let mut test_key = [0u8; 100];

    crypto_kem_dec(&mut test_key, &mut c, &mut sk);
}
