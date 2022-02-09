use std::error;

use crate::controlbits::controlbitsfrompermutation;
use crate::{
    crypto_hash::shake256,
    decrypt::decrypt,
    encrypt::encrypt,
    params::{COND_BYTES, GFBITS, IRR_BYTES, SYND_BYTES, SYS_N, SYS_T},
    pk_gen::pk_gen,
    randombytes::randombytes,
    sk_gen::genpoly_gen,
    util::{load4, load_gf, store8, store_gf},
};

/// KEM Encapsulation.
///
/// Given a public key `pk`, sample a shared key.
/// This shared key is returned through parameter `key` whereas
/// the ciphertext (meant to be used for decapsulation) is returned as `c`.
pub fn crypto_kem_enc(c: &mut [u8], key: &mut [u8], pk: &[u8]) -> Result<(), Box<dyn error::Error>> {
    let mut two_e = [0u8; 1 + SYS_N / 8];
    two_e[0] = 2;

    let mut one_ec = [0u8; 1 + SYS_N / 8 + (SYND_BYTES + 32)];
    one_ec[0] = 1;

    encrypt(c, pk, &mut two_e[1..])?;

    shake256(&mut c[SYND_BYTES..], &two_e)?;

    for i in 1..=SYS_N / 8 {
        one_ec[i] = two_e[i];
    }

    let mut j = 0;
    for i in (1 + SYS_N / 8)..(1 + SYS_N / 8 + SYND_BYTES + 32) {
        one_ec[i] = c[j];
        j += 1;
    }

    shake256(key, &one_ec)?;

    Ok(())
}

/// KEM Decapsulation.
///
/// Given a secret key `sk` and a ciphertext `c`,
/// determine the shared text `key` negotiated by both parties.
pub fn crypto_kem_dec(key: &mut [u8], c: &[u8], sk: &[u8]) -> Result<(), Box<dyn error::Error>> {
    let mut conf = [0u8; 32];
    let mut two_e = [0u8; 1 + SYS_N / 8];
    two_e[0] = 2;

    let mut preimage = [0u8; 1 + SYS_N / 8 + (SYND_BYTES + 32)];

    let ret_decrypt: u8 = decrypt(&mut two_e[1..], &sk[40..], c);

    shake256(&mut conf, &two_e)?;

    let mut ret_confirm: u8 = 0;
    for i in 0..32 {
        ret_confirm |= conf[i] ^ c[SYND_BYTES + i];
    }

    let mut m = (ret_decrypt | ret_confirm) as u16;
    m = m.wrapping_sub(1);
    m >>= 8;

    let mut index = 0;
    preimage[index] = (m & 1) as u8;
    index += 1;

    let s = &sk[40 + IRR_BYTES + COND_BYTES..];

    for i in 0..SYS_N / 8 {
        preimage[index] = (!m as u8 & s[i]) | (m as u8 & two_e[i + 1]);
        index += 1;
    }

    for i in 0..SYND_BYTES + 32 {
        preimage[index] = c[i];
        index += 1;
    }

    shake256(key, &preimage)
}

/// Compute the logarithm of `x` w.r.t. base 2.
fn log2(mut x: usize) -> usize {
    // TODO this does not look efficient
    while x.count_ones() != 1 {
        x += 1;
    }
    let mut log = 0;
    while x != 0 {
        x >>= 1;
        log += 1;
    }
    log - 1
}

/// KEM Keypair generation.
///
/// Generate some public and secret key.
/// The public key is meant to be shared with any party,
/// but access to the secret key must be limited to the generating party.
pub fn crypto_kem_keypair(pk: &mut [u8], sk: &mut [u8]) -> Result<(), Box<dyn error::Error>> {
    let mut seed = [0u8; 33];
    seed[0] = 64;

    const S_BASE: usize = 32 + 8 + IRR_BYTES + COND_BYTES;

    const SEED: usize = SYS_N / 8 + (1 << GFBITS) * 4 + SYS_T * 2;
    const IRR_POLYS: usize = SYS_N / 8 + (1 << GFBITS) * 4;
    const PERM: usize = SYS_N / 8;

    let mut r = [0u8; SYS_N / 8 + (1 << GFBITS) * 4 + SYS_T * 2 + 32];
    let mut pivots: u64 = 0;

    let mut f = [0u16; SYS_T];
    let mut irr = [0u16; SYS_T];

    let mut perm = [0u32; 1 << GFBITS];
    let mut pi = [0i16; 1 << GFBITS];

    randombytes(&mut seed[1..], 32)?;

    loop {
        // expanding and updating the seed
        shake256(&mut r[..], &seed[0..33])?;

        (&mut sk[..32]).clone_from_slice(&seed[1..]);
        (&mut seed[1..]).clone_from_slice(&r[r.len() - 32..]);

        // generating irreducible polynomial

        for (i, chunk) in r[IRR_POLYS..SEED].chunks(2).enumerate() {
            f[i] = load_gf(chunk);
        }

        if genpoly_gen(&mut irr, &mut f) != 0 {
            continue;
        }

        for (i, chunk) in sk[32 + 8..32 + 8 + 2 * SYS_T].chunks_mut(2).enumerate() {
            store_gf(chunk, irr[i]);
        }

        // generating permutation

        for (i, chunk) in r[PERM..IRR_POLYS].chunks(4).enumerate() {
            perm[i] = load4(chunk);
        }

        if pk_gen(pk, &mut sk[(32 + 8)..], &mut perm, &mut pi, &mut pivots) != 0 {
            continue;
        }

        let m = log2(pi.len());
        let count = (((2 * m - 1) * (1 << (m - 1))) + 7) / 8;
        controlbitsfrompermutation(
            &mut sk[(32 + 8 + IRR_BYTES)..(32 + 8 + IRR_BYTES + count)],
            &mut pi,
            GFBITS,
            1 << GFBITS,
        );

        // storing the random string s

        sk[S_BASE..(S_BASE + SYS_N / 8)].clone_from_slice(&r[0..SYS_N / 8]);

        // storing positions of the 32 pivots

        store8(&mut sk[32..40], pivots);

        break;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "mceliece8192128f", test))]
    use super::*;
    #[cfg(all(feature = "mceliece8192128f", test))]
    use crate::randombytes::randombytes_init;

    #[cfg(all(feature = "mceliece8192128f", test))]
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
            236, 53, 216, 229, 94, 183, 172, 233, 134, 102, 148, 252, 9, 21, 64, 46, 160, 114, 10,
            133, 197, 163, 219, 138, 147, 214, 39, 240, 67, 42, 69, 46,
        ];

        crypto_kem_dec(&mut test_key, &mut c, &mut sk);

        assert_eq!(test_key, compare_key);
    }

    #[cfg(all(feature = "mceliece8192128f", test))]
    pub fn test_crypto_kem_enc() -> Result<(), Box<dyn error::Error>> {
        use crate::{
            api::{CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES},
            encrypt_array::PK_INPUT,
        };

        let mut c = [0u8; CRYPTO_CIPHERTEXTBYTES];
        let mut ss = [0u8; CRYPTO_BYTES];
        let mut pk = PK_INPUT.to_vec();
        assert_eq!(pk.len(), CRYPTO_PUBLICKEYBYTES);

        let mut compare_key: [u8; 32] = [
            236, 53, 216, 229, 94, 183, 172, 233, 134, 102, 148, 252, 9, 21, 64, 46, 160, 114, 10,
            133, 197, 163, 219, 138, 147, 214, 39, 240, 67, 42, 69, 46,
        ];
        let mut compare_s: [u8; CRYPTO_CIPHERTEXTBYTES] = [
            242, 32, 240, 115, 213, 142, 119, 195, 175, 92, 54, 108, 148, 206, 223, 242, 89, 228,
            20, 76, 143, 186, 142, 203, 248, 51, 88, 44, 41, 34, 66, 148, 49, 215, 188, 202, 21,
            213, 135, 64, 92, 246, 70, 65, 28, 225, 19, 149, 13, 231, 177, 94, 146, 172, 255, 139,
            219, 153, 56, 91, 225, 145, 127, 126, 230, 140, 186, 88, 195, 37, 5, 40, 44, 86, 141,
            103, 238, 41, 200, 75, 7, 152, 140, 157, 77, 2, 205, 90, 33, 84, 74, 48, 80, 210, 75,
            112, 1, 179, 35, 47, 188, 83, 79, 32, 51, 171, 122, 16, 171, 78, 92, 129, 106, 12, 231,
            177, 251, 219, 70, 210, 219, 181, 250, 201, 52, 188, 250, 87, 198, 117, 38, 85, 100,
            175, 52, 0, 234, 77, 206, 215, 230, 139, 237, 176, 175, 76, 82, 162, 91, 251, 166, 190,
            33, 98, 170, 122, 219, 142, 246, 133, 239, 188, 17, 148, 7, 166, 147, 138, 249, 4, 99,
            11, 126, 117, 90, 157, 47, 116, 150, 240, 97, 41, 238, 117, 56, 208, 145, 68, 16, 123,
            213, 27, 199, 37, 214, 213, 167, 63, 65, 157, 130, 119, 187, 193, 149, 255, 76, 127,
            62, 221, 8, 98, 22, 201, 15, 40, 199, 142, 3, 196, 150, 181, 110, 102, 89, 220, 149,
            197, 247, 197, 26, 55, 29, 54, 186, 217, 188, 23, 87, 194,
        ];

        // set the same seed as in C implementation
        let mut entropy_input = [0u8; 48];
        let mut personalization_string = [0u8; 48];
        entropy_input = [
            6, 21, 80, 35, 77, 21, 140, 94, 201, 85, 149, 254, 4, 239, 122, 37, 118, 127, 46, 36,
            204, 43, 196, 121, 208, 157, 134, 220, 154, 188, 253, 231, 5, 106, 140, 38, 111, 158,
            249, 126, 208, 133, 65, 219, 210, 225, 255, 161,
        ];

        randombytes_init(&entropy_input, &personalization_string, 256)?;

        let mut second_seed = [0u8; 33];
        second_seed[0] = 64;

        randombytes(&mut second_seed[1..], 32)?;

        // call
        crypto_kem_enc(&mut c, &mut ss, &mut pk);

        assert_eq!(ss, compare_key);

        assert_eq!(c, compare_s);

        Ok(())
    }

    #[cfg(all(feature = "mceliece8192128f", test))]
    pub fn test_crypto_kem_keypair() -> Result<(), Box<dyn error::Error>> {
        use crate::{
            api::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES},
            operations_arrays::{COMPARE_PK, COMPARE_SK, PK_INPUT, SK_INPUT},
        };

        let mut pk_input = PK_INPUT.to_vec();
        assert_eq!(pk_input.len(), CRYPTO_PUBLICKEYBYTES);

        let mut sk_input = SK_INPUT.to_vec();
        assert_eq!(sk_input.len(), CRYPTO_SECRETKEYBYTES);

        let mut entropy_input = [0u8; 48];
        let mut personalization_string = [0u8; 48];
        entropy_input = [
            6, 21, 80, 35, 77, 21, 140, 94, 201, 85, 149, 254, 4, 239, 122, 37, 118, 127, 46, 36,
            204, 43, 196, 121, 208, 157, 134, 220, 154, 188, 253, 231, 5, 106, 140, 38, 111, 158,
            249, 126, 208, 133, 65, 219, 210, 225, 255, 161,
        ];

        let compare_sk = COMPARE_SK.to_vec();
        assert_eq!(compare_sk.len(), CRYPTO_SECRETKEYBYTES);

        let compare_pk = COMPARE_PK.to_vec();
        assert_eq!(compare_pk.len(), CRYPTO_PUBLICKEYBYTES);

        randombytes_init(&entropy_input, &personalization_string, 256)?;

        crypto_kem_keypair(&mut pk_input, &mut sk_input);

        assert_eq!(compare_sk, sk_input);
        assert_eq!(compare_pk, pk_input);

        Ok(())
    }
}
