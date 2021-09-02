use crate::util::load8;

/*
  This file is for Benes network related functions

  For the implementation strategy, see
  https://eprint.iacr.org/2017/793.pdf
*/

/* middle layers of the benes network */
fn layer_in(data: &mut [[u64; 2]; 64], bits: &mut u64, lgs: usize) {
    let (mut i, mut j, mut s): (usize, usize, usize) = (0, 0, 0);
    let mut d: u64;

    s = 1 << lgs;

    while i < 64 {
        j = i;
        while j < i + s {
            d = data[0][j + 0] ^ data[0][j + s];
            d &= *bits + 1 as u64; // todo review stmt
            data[0][j + 0] ^= d;
            data[0][j + s] ^= d;

            d = data[1][j + 0] ^ data[1][j + s];
            d &= *bits + 1 as u64;
            data[1][j + 0] ^= d;
            data[1][j + s] ^= d;

            j += 1;
        }
        i += s * 2;
    }
}

fn layer_ex(data: &mut [u64], bits: &mut u64, lgs: usize) {
    let (mut i, mut j, mut s): (usize, usize, usize) = (0, 0, 0);
    let mut d: u64;

    s = 1 << lgs;

    while i < 64 {
        j = i;
        while j < i + s {
            d = data[j + 0] ^ data[j + s];
            d &= *bits + 1 as u64;
            data[j + 0] ^= d;
            data[j + s] ^= d;

            j += 1;
        }
        i += s * 2;
    }
}

/* input: r, sequence of bits to be permuted */
/*        bits, condition bits of the Benes network */
/*        rev, 0 for normal application; !0 for inverse */
/* output: r, permuted bits */
/*pub fn apply_benes(r: &[u8], bits: &[u8], rev: usize) {

    let (mut i, mut iter, mut inc): (usize, usize, i32) = (0, 0, 0);

    let r_ptr = r;
    let mut bits_ptr: &[u8];

    let r_int_v: &mut [[u64; 2]; 64];
    let r_int_h: &mut [[u64; 2]; 64];
    let b_int_v: &mut [u64; 64];
    let b_int_h: &mut [u64; 64];

    // todo check on ptr arithmetic
    if rev != 0 {
        bits_ptr = bits + 12288;
        inc = -1024;
    } else {
        bits_ptr = bits;
        inc = 0;
    }

    for i in 0..64 {
        r_int_v[0][i] = load8(r_ptr);
        r_int_v[1][i] = load8(*r_ptr + i*16 + 8);
    }
}*/
