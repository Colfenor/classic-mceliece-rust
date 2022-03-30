use crate::{
    benes::support_gen,
    bm::bm,
    gf::gf_iszero,
    macros::sub,
    params::{COND_BYTES, IRR_BYTES, SYND_BYTES, SYS_N, SYS_T},
    root::root,
    synd::synd,
    util::load_gf,
};
use std::error;

/// Niederreiter decryption with the Berlekamp decoder.
///
/// It takes as input the secret key `sk` and a ciphertext `c`.
/// It returns an error vector in `e` and the return value indicates success (0) or failure (1)
pub(crate) fn decrypt(e: &mut [u8; SYS_N/8], sk: &[u8; IRR_BYTES + COND_BYTES], c: &[u8; SYND_BYTES]) -> Result<u8, Box<dyn error::Error>> {
    let mut t: u16;
    let mut w: i32 = 0;

    let mut r = [0u8; SYS_N / 8];

    let mut g = [0u16; SYS_T + 1];
    let mut l = [0u16; SYS_N];

    let mut s = [0u16; SYS_T * 2];
    let mut s_cmp = [0u16; SYS_T * 2];
    let mut locator = [0u16; SYS_T + 1];
    let mut images = [0u16; SYS_N];

    for i in 0..SYND_BYTES {
        r[i] = c[i];
    }

    for i in SYND_BYTES..SYS_N / 8 {
        r[i] = 0;
    }

    for (i, chunk) in sk.chunks(2).take(SYS_T).enumerate() {
        g[i] = load_gf(sub!(chunk, 0, 2));
    }
    g[SYS_T] = 1;

    support_gen(&mut l, sub!(sk, IRR_BYTES, COND_BYTES))?;

    synd(&mut s, &mut g, &mut l, &r);

    bm(&mut locator, &mut s);

    root(&mut images, &mut locator, &mut l);

    for i in 0..SYS_N / 8 {
        e[i] = 0;
    }

    for i in 0..SYS_N {
        t = gf_iszero(images[i]) & 1;

        e[i / 8] |= (t << (i % 8)) as u8;
        w += t as i32;
    }

    synd(&mut s_cmp, &mut g, &mut l, e);

    let mut check = w as u16;
    check ^= SYS_T as u16;

    for i in 0..SYS_T * 2 {
        check |= s[i] ^ s_cmp[i];
    }

    check = check.wrapping_sub(1);
    check >>= 15;

    Ok((check ^ 1) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{CRYPTO_CIPHERTEXTBYTES, CRYPTO_SECRETKEYBYTES};
    use crate::crypto_hash::shake256;
    use std::error;

    #[test]
    fn test_decrypt() -> Result<(), Box<dyn error::Error>> {
        let sk = crate::TestData::new().u8vec("mceliece8192128f_sk1"); // TODO: sk has wrong size … IRR_BYTES + COND_BYTES required
        assert_eq!(sk.len(), CRYPTO_SECRETKEYBYTES + 40);

        let mut c = crate::TestData::new().u8vec("mceliece8192128f_ct1");
        assert_eq!(c.len(), CRYPTO_CIPHERTEXTBYTES);

        let expected_error_vector = crate::TestData::new().u8vec("mceliece8192128f_decrypt_errvec");
        assert_eq!(expected_error_vector.len(), 1 + SYS_N / 8);

        let mut actual_error_vector = [0u8; 1 + SYS_N / 8];
        actual_error_vector[0] = 2;

        decrypt(sub!(mut actual_error_vector, 1, SYS_N/8), sub!(sk, 40, IRR_BYTES + COND_BYTES), sub!(mut c, 0, SYND_BYTES))?;

        assert_eq!(actual_error_vector.to_vec(), expected_error_vector);

        // test crypto_hash
        let mut conf = [0u8; 32];

        shake256(&mut conf, &actual_error_vector[0..1025])
    }
}
