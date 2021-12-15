use crate::{
    params::{PK_NROWS, PK_ROW_BYTES, SYND_BYTES, SYS_N, SYS_T},
    pk_gen::same_mask,
    util::load_gf,
};

/* output: e, an error vector of weight t */
fn gen_e(e: &mut [u8]) {
    let mut ind = [0u16; SYS_T];
    let mut bytes = [0u8; SYS_T];
    let mut val = [0u8; SYS_T];
    let mut mask: u8 = 0;

    let mut eq = 0;

    loop {
        // TODO randombytes CALL
        let mut i = 1;
        for chunk in bytes.chunks_mut(i * 2) {
            ind[i] = load_gf(chunk);
            i += 1;
            if i == SYS_T - 1 {
                break;
            }
        }

        eq = 0;

        for i in 1..SYS_T {
            for j in 0..i {
                if ind[i] == ind[j] {
                    eq = 1;
                }
            }
        }

        if eq == 0 {
            break;
        }
    }

    for j in 0..SYS_T {
        val[j] = 1 << (ind[j] & 7);
    }

    for i in 0..SYS_N / 8 {
        e[i] = 0;

        for j in 0..SYS_T {
            mask = same_mask(i as u16, (ind[j] >> 3)) as u8;

            e[i] |= val[j] & mask;
        }
    }
}

/* input: public key pk, error vector e */
/* output: syndrome s */
fn syndrome(s: &mut [u8], pk: &mut [u8], e: &mut [u8]) {
    let mut b: u8 = 0;
    let mut row = [0u8; SYS_N / 8];

    let mut pk_ptr = pk;

    for i in 0..SYND_BYTES {
        s[i] = 0;
    }

    for i in 0..PK_NROWS {
        for j in 0..SYS_N / 8 {
            row[j] = 0;
        }

        for j in 0..PK_ROW_BYTES {
            row[SYS_N / 8 - PK_ROW_BYTES + j] = pk_ptr[j];
        }

        row[i / 8] |= 1 << (i % 8);

        b = 0;
        for j in 0..SYS_N / 8 {
            b ^= row[j] & e[j];
        }

        b ^= b >> 4;
        b ^= b >> 2;
        b ^= b >> 1;
        b &= 1;

        s[i / 8] |= (b << (i % 8));

        pk_ptr = &mut pk_ptr[PK_ROW_BYTES..];
    }
}

pub fn encrypt(s: &mut [u8], pk: &mut [u8], e: &mut [u8]) {
    gen_e(e);

    print!("encrypt e: positions");
    for k in 0..SYS_N {
        if e[k / 8] & (1 << (k & 7)) == 1 {
            print!("{}", k);
        }
    }
    println!("");

    syndrome(s, pk, e);
}
