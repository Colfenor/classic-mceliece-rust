use rand::{CryptoRng, RngCore};

use crate::{
    common::crypto_hash::shake256,
    macros::sub,
    mceliece348864::{
        controlbits::controlbitsfrompermutation,
        decrypt::decrypt,
        encrypt::encrypt,
        pk_gen::pk_gen,
        sk_gen::genpoly_gen,
        util::{load4, load_gf, store_gf},
    },
};

/// The number of bytes required to store the public key
pub const CRYPTO_PUBLICKEYBYTES: usize = 261120;
/// The number of bytes required to store the secret key
pub const CRYPTO_SECRETKEYBYTES: usize = 6492;
/// The number of bytes required to store the ciphertext resulting from the encryption
pub const CRYPTO_CIPHERTEXTBYTES: usize = 128;
/// The number of bytes required to store the shared secret negotiated between both parties
pub const CRYPTO_BYTES: usize = 32;

/// Name of the variant
pub const CRYPTO_PRIMITIVE: &str = "mceliece348864";

pub const GFBITS: usize = 12;
pub const SYS_N: usize = 3488;
pub const SYS_T: usize = 64;
pub const COND_BYTES: usize = (1 << (GFBITS - 4)) * (2 * GFBITS - 1);
pub const IRR_BYTES: usize = SYS_T * 2;
pub const PK_NROWS: usize = SYS_T * GFBITS;
pub const PK_NCOLS: usize = SYS_N - PK_NROWS;
pub const PK_ROW_BYTES: usize = (PK_NCOLS + 7) / 8;
pub const SYND_BYTES: usize = (PK_NROWS + 7) / 8;
pub const GFMASK: usize = (1 << GFBITS) - 1;

/// KEM Encapsulation.
///
/// Given a public key `pk`, sample a shared key.
/// This shared key is returned through parameter `key` whereas
/// the ciphertext (meant to be used for decapsulation) is returned as `c`.
pub fn crypto_kem_enc<R: CryptoRng + RngCore>(
    c: &mut [u8; CRYPTO_CIPHERTEXTBYTES],
    key: &mut [u8; CRYPTO_BYTES],
    pk: &[u8; CRYPTO_PUBLICKEYBYTES],
    rng: &mut R,
) {
    let mut two_e = [0u8; 1 + SYS_N / 8];
    two_e[0] = 2;

    let mut one_ec = [0u8; 1 + SYS_N / 8 + (SYND_BYTES + 32)];
    one_ec[0] = 1;

    encrypt(c, pk, sub!(mut two_e, 1, SYS_N / 8), rng);

    shake256(&mut c[SYND_BYTES..SYND_BYTES + 32], &two_e);

    one_ec[1..1 + SYS_N / 8].copy_from_slice(&two_e[1..1 + SYS_N / 8]);
    one_ec[1 + SYS_N / 8..1 + SYS_N / 8 + SYND_BYTES + 32].copy_from_slice(&c[0..SYND_BYTES + 32]);

    shake256(&mut key[0..32], &one_ec);
}

/// KEM Decapsulation.
///
/// Given a secret key `sk` and a ciphertext `c`,
/// determine the shared text `key` negotiated by both parties.
pub fn crypto_kem_dec(
    key: &mut [u8; CRYPTO_BYTES],
    c: &[u8; CRYPTO_CIPHERTEXTBYTES],
    sk: &[u8; CRYPTO_SECRETKEYBYTES],
) -> u8 {
    let mut conf = [0u8; 32];
    let mut two_e = [0u8; 1 + SYS_N / 8];
    two_e[0] = 2;

    let mut preimage = [0u8; 1 + SYS_N / 8 + (SYND_BYTES + 32)];

    let ret_decrypt: u8 = decrypt(
        sub!(mut two_e, 1, SYS_N / 8),
        sub!(sk, 40, IRR_BYTES + COND_BYTES),
        sub!(c, 0, SYND_BYTES),
    );

    shake256(&mut conf[0..32], &two_e);

    let mut ret_confirm: u8 = 0;
    for i in 0..32 {
        ret_confirm |= conf[i] ^ c[SYND_BYTES + i];
    }

    let mut m = (ret_decrypt | ret_confirm) as u16;
    m = m.wrapping_sub(1);
    m >>= 8;

    preimage[0] = (m & 1) as u8;

    let s = &sk[40 + IRR_BYTES + COND_BYTES..];

    for i in 0..SYS_N / 8 {
        preimage[1 + i] = (!m as u8 & s[i]) | (m as u8 & two_e[1 + i]);
    }

    (&mut preimage[1 + (SYS_N / 8)..])[0..SYND_BYTES + 32].copy_from_slice(&c[0..SYND_BYTES + 32]);

    shake256(&mut key[0..32], &preimage);

    0
}

/// KEM Keypair generation.
///
/// Generate some public and secret key.
/// The public key is meant to be shared with any party,
/// but access to the secret key must be limited to the generating party.
///
/// The structure of the secret key is given by the following segments:
/// (32 bytes seed, 8 bytes pivots, IRR_BYTES bytes, COND_BYTES bytes, SYS_N/8 bytes).
/// The structure of the public key is simple: a matrix of PK_NROWS times PK_ROW_BYTES bytes.
pub fn crypto_kem_keypair<R: CryptoRng + RngCore>(
    pk: &mut [u8; CRYPTO_PUBLICKEYBYTES],
    sk: &mut [u8; CRYPTO_SECRETKEYBYTES],
    rng: &mut R,
) {
    let mut seed = [0u8; 33];
    seed[0] = 64;

    const S_BASE: usize = 32 + 8 + IRR_BYTES + COND_BYTES;

    const SEED: usize = SYS_N / 8 + (1 << GFBITS) * 4 + SYS_T * 2;
    const IRR_POLYS: usize = SYS_N / 8 + (1 << GFBITS) * 4;
    const PERM: usize = SYS_N / 8;

    let mut r = [0u8; SEED + 32];

    let mut f = [0u16; SYS_T];
    let mut irr = [0u16; SYS_T];

    let mut perm = [0u32; 1 << GFBITS];
    let mut pi = [0i16; 1 << GFBITS];

    rng.fill_bytes(&mut seed[1..]);

    loop {
        // expanding and updating the seed
        shake256(&mut r[..], &seed[0..33]);

        sk[..32].clone_from_slice(&seed[1..]);
        seed[1..].clone_from_slice(&r[r.len() - 32..]);

        // generating irreducible polynomial

        for (i, chunk) in r[IRR_POLYS..SEED].chunks(2).enumerate() {
            f[i] = load_gf(sub!(chunk, 0, 2));
        }

        if genpoly_gen(&mut irr, &mut f) != 0 {
            continue;
        }

        for (i, chunk) in sk[40..40 + IRR_BYTES].chunks_mut(2).enumerate() {
            store_gf(sub!(mut chunk, 0, 2), irr[i]);
        }

        // generating permutation

        for (i, chunk) in r[PERM..IRR_POLYS].chunks(4).enumerate() {
            perm[i] = load4(sub!(chunk, 0, 4));
        }

        if pk_gen(pk, sub!(mut sk, 40, IRR_BYTES), &mut perm, &mut pi) != 0 {
            continue;
        }

        controlbitsfrompermutation(
            &mut sk[(40 + IRR_BYTES)..(40 + IRR_BYTES + COND_BYTES)],
            &mut pi,
            GFBITS,
            1 << GFBITS,
        );

        // storing the random string s

        sk[S_BASE..(S_BASE + SYS_N / 8)].clone_from_slice(&r[0..SYS_N / 8]);

        // storing positions of the 32 pivots

        let pivots = 0xFFFFFFFFu64;

        *sub!(mut sk, 32, 8) = pivots.to_le_bytes();

        break;
    }
}

mod benes;
mod bm;
mod controlbits;
mod decrypt;
mod encrypt;
mod gf;
mod pk_gen;
mod root;
mod sk_gen;
mod synd;
mod util;
