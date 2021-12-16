use crate::{
    api::CRYPTO_SECRETKEYBYTES,
    benes::support_gen,
    bm::bm,
    gf::gf_iszero,
    params::{SYND_BYTES, SYS_N, SYS_T},
    root::root,
    synd::synd,
    util::load_gf,
};

pub fn decrypt(e: &mut [u8], sk: &mut [u8; CRYPTO_SECRETKEYBYTES + 40], c: &mut [u8]) -> i32 {
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
        if i == SYS_T - 1 {
            break;
        }
    }
    g[SYS_T] = 1;

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
            print!("{}", k);
        }
    }
    println!("");

    synd(&mut s_cmp, &mut g, &mut L, e);

    check = w as u16;
    check ^= SYS_T as u16;

    for i in 0..SYS_T * 2 {
        check |= s[i] ^ s_cmp[i];
    }

    check -= 1;
    check >>= 15;

    return (check ^ 1) as i32;
}
