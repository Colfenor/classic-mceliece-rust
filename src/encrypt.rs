use std::error;

use crate::{
    api::{CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES},
    params::{PK_NROWS, PK_ROW_BYTES, SYND_BYTES, SYS_N, SYS_T},
    randombytes::{randombytes, randombytes_init},
    util::load_gf,
};

fn same_mask_u8(x: u16, y: u16) -> u8 {
    let mut mask = 0u32;

    mask = (x ^ y) as u32;
    mask = mask.wrapping_sub(1);
    //mask >>= 31;
    mask = mask.overflowing_shr(31).0;
    mask = 0u32.wrapping_sub(mask);
    // return value either 0 or u8::MAX

    (mask & 0xFF) as u8
}

/* output: e, an error vector of weight t */
fn gen_e(e: &mut [u8]) {
    let mut ind = [0u16; SYS_T];
    let mut bytes = [0u8; SYS_T * 2];
    let mut val = [0u8; SYS_T];
    let mut mask: u8 = 0;

    let mut eq = 0;
    let mut countr = 0;

    loop {
        countr += 1;
        match randombytes(&mut bytes, SYS_T * 2) {
            Err(e) => {
                println!("{:?}", e);
                break;
            }
            Ok(()) => {}
        }

        let mut i = 0;
        for chunk in bytes.chunks_mut((i + 1) * 2) {
            ind[i] = load_gf(chunk);
            i += 1;
            if i == SYS_T {
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
            //println!("countr:{}", countr);
            break;
        }
    }

    for j in 0..SYS_T {
        val[j] = 1 << (ind[j] & 7);
        //println!("j:{} val:{}", j, val[j])
    }

    for i in 0..SYS_N / 8 {
        e[i] = 0;

        for j in 0..SYS_T {
            mask = same_mask_u8(i as u16, ind[j] >> 3) as u8;
            //println!("i:{} j:{} mask:{}", i, j, mask);

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

        s[i / 8] |= b << (i % 8);

        pk_ptr = &mut pk_ptr[PK_ROW_BYTES..];
    }
}

pub fn encrypt(s: &mut [u8], pk: &mut [u8], e: &mut [u8]) {
    gen_e(e);

    print!("encrypt e: positions");
    for k in 0..SYS_N {
        if e[k / 8] & (1 << (k & 7)) == 1 {
            print!(" {}", k);
        }
    }
    println!("");

    syndrome(s, pk, e);
}

// unsigned char two_e[ 1 + SYS_N/8 ] = {2};

#[test]
pub fn test_encrypt() -> Result<(), Box<dyn error::Error>> {
    use crate::encrypt_array::PK_INPUT;

    let mut entropy_input = [0u8; 48];
    for i in 0..48u8 {
        entropy_input[i as usize] = i;
    }
    randombytes_init(entropy_input)?;

    let mut two_e = [0u8; 1 + SYS_N / 8];
    two_e[0] = 2;

    let mut c = [0u8; CRYPTO_CIPHERTEXTBYTES];
    let mut pk = PK_INPUT.to_vec();

    encrypt(&mut c, &mut pk, &mut two_e);

    /*for i in 0..c.len() {
        println!("i:{} c:{}", i, c[i]);
    }*/

    Ok(())
}
