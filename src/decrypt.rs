use crate::{
    api::{CRYPTO_CIPHERTEXTBYTES, CRYPTO_SECRETKEYBYTES},
    benes::support_gen,
    bm::bm,
    crypto_hash::{self, shake256},
    gf::gf_iszero,
    params::{SYND_BYTES, SYS_N, SYS_T},
    root::root,
    synd::synd,
    util::load_gf,
};

// todo write function for array output, which
// takes array and it's length

/* Niederreiter decryption with the Berlekamp decoder */
/* intput: sk, secret key */
/*         c, ciphertext */
/* output: e, error vector two_e[ 1 + SYS_N/8 ] = {2}; */
/* return: 0 for success; 1 for failure */
pub fn decrypt(e: &mut [u8], mut sk: &mut [u8], c: &mut [u8]) -> u8 {
    let mut check: u16 = 0;
    let mut t: u16 = 0;
    let mut w: i32 = 0;

    let mut r = [0u8; SYS_N / 8];

    let mut g = [0u16; SYS_T + 1];
    let mut L = [0u16; SYS_N];

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

    let mut i = 0;
    for chunk in sk.chunks_mut(2) {
        g[i] = load_gf(chunk);
        i += 1;
        if i == SYS_T + 1 {
            break;
        }
    }
    g[SYS_T] = 1;
    // g array matches :)
    sk = &mut sk[256..];

    /*println!("sk input: ");
    for i in 0..13864 {
        println!("{}", sk[i]);
    }
    println!("ENDI");*/

    support_gen(&mut L, sk);

    synd(&mut s, &mut g, &mut L, &r);

    bm(&mut locator, &mut s);

    root(&mut images, &mut locator, &mut L);

    for i in 0..SYS_N / 8 {
        e[i] = 0;
    }

    for i in 0..SYS_N {
        t = gf_iszero(images[i]) & 1;

        e[i / 8] |= (t << (i % 8)) as u8;
        w += t as i32;
    }

    print!("decrypt e: positions");
    for k in 0..SYS_N {
        if e[k / 8] & (1 << (k & 7)) == 1 {
            print!(" {}", k);
        }
    }
    println!("");

    synd(&mut s_cmp, &mut g, &mut L, e);

    check = w as u16;
    check ^= SYS_T as u16;

    for i in 0..SYS_T * 2 {
        check |= s[i] ^ s_cmp[i];
    }

    check = check.wrapping_sub(1);
    check >>= 15;

    return (check ^ 1) as u8;
}

#[test]
pub fn test_decrypt() {
    use crate::decrypt_arrays::{C_INPUT, SK_INPUT, TWO_E_COMPARE};

    //let mut sk = [0u8; CRYPTO_SECRETKEYBYTES]; // + 40
    let mut sk = SK_INPUT.to_vec();
    assert_eq!(sk.len(), CRYPTO_SECRETKEYBYTES + 40);

    let mut c = C_INPUT.to_vec();
    assert_eq!(c.len(), CRYPTO_CIPHERTEXTBYTES);

    let mut two_e_compare = TWO_E_COMPARE.to_vec();
    assert_eq!(two_e_compare.len(), 1 + SYS_N / 8);

    let mut two_e = [0u8; 1 + SYS_N / 8];
    two_e[0] = 2;

    /*println!("skp input: ");
    for i in 0..sk.len() {
        println!("{}", sk[i]);
    }
    println!("ENDI");*/

    decrypt(&mut two_e[1..], &mut sk[40..], &mut c);

    assert_eq!(two_e.to_vec(), two_e_compare);

    // test crypto_hash
    let mut conf = [0u8; 32];

    shake256(&mut conf, &two_e[0..1025]);

    /*println!("crypto: ");
    for i in 0..32 {
        println!("{}", conf[i]);
    }
    println!("ENDI");*/
}
