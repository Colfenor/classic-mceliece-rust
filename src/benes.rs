use crate::{
    gf::GFBITS,
    transpose,
    util::{load8, store8},
};
/*
  This file is for Benes network related functions

  For the implementation strategy, see
  https://eprint.iacr.org/2017/793.pdf
*/

/* middle layers of the benes network */
fn layer_in(data: &mut [[u64; 64]; 2], bits: &mut [u64], lgs: usize) {
    let (mut i, mut j, mut s): (usize, usize, usize) = (0, 0, 0);
    let mut d: u64;
    let mut index = 0;

    s = 1 << lgs;

    while i < 64 {
        j = i;
        while j < i + s {
            d = data[0][j + 0] ^ data[0][j + s];

            d &= bits[index];
            index += 1;

            data[0][j + 0] ^= d;
            data[0][j + s] ^= d;

            d = data[1][j + 0] ^ data[1][j + s];

            d &= bits[index];
            index += 1;

            data[1][j + 0] ^= d;
            data[1][j + s] ^= d;

            j += 1;
        }
        i += s * 2;
    }
}

fn layer_ex(data: &mut [u64], bits: &mut [u64], lgs: usize) {
    let (mut i, mut j, mut s): (usize, usize, usize) = (0, 0, 0);
    let mut d: u64;
    let mut index = 0;
    s = 1 << lgs;

    while i < 64 {
        j = i;
        while j < i + s {
            d = data[j + 0] ^ data[j + s];

            d &= bits[index];
            index += 1;

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
// todo fixe größe angeben, und rückgabewert neues array mit fixer größe
//#define crypto_kem_mceliece8192128f_ref_SECRETKEYBYTES 14120 -> sk
//ret_decrypt = decrypt(e, sk + 40, c);

//let mut subbits = [0u8; 3584];
//subbits.copy_from_slice(&bits[0..3584]);

pub fn apply_benes(r: &mut [u8; (1 << GFBITS) / 8], bits: &[u8; 14160], rev: usize) {
    let mut i: usize = 0;

    let mut r_int_v = [[0u64; 64]; 2];
    let mut r_int_h = [[0u64; 64]; 2];
    let mut b_int_v = [0u64; 64];
    let mut b_int_h = [0u64; 64];

    let mut calc_index = if rev == 0 { 0 } else { 12288 };

    /*for i in 0..64 {
        let mut r_ptr: Vec<u8> = Vec::with_capacity(i*16 + 0);
        let mut x = r_ptr.copy_from_slice(&r[0..i*16]);
        function(x); // accepts &[u8]

        r_int_v[0][i] = load8();
        //r_int_v[1][i] = load8();
    }*/

    for chunk in r.chunks_mut(16) {
        let (subchunk1, subchunk2) = chunk.split_at_mut(8);
        r_int_v[1][i] = load8(subchunk1);
        r_int_v[0][i] = load8(subchunk2);
    }

    transpose::transpose(&mut r_int_h[0], r_int_v[0]);
    transpose::transpose(&mut r_int_h[1], r_int_v[1]);

    let mut iter = 0;
    while iter <= 6 {
        for chunk in bits[calc_index..(calc_index + 512)].chunks(8) {
            b_int_v[i] = load8(chunk);
        }

        calc_index = if rev == 0 {
            calc_index
        } else {
            calc_index - 1024
        };

        transpose::transpose(&mut b_int_h, b_int_v);

        layer_ex(&mut r_int_h[0], &mut b_int_h, iter);

        iter += 1;
    }

    transpose::transpose(&mut r_int_v[0], r_int_h[0]);
    transpose::transpose(&mut r_int_v[1], r_int_h[1]);

    let mut iter: usize = 0;
    while iter <= 5 {
        for chunk in bits[calc_index..(calc_index + 512)].chunks(8) {
            b_int_v[i] = load8(chunk);
        }
        calc_index = if rev == 0 {
            calc_index
        } else {
            calc_index - 1024
        };

        layer_in(&mut r_int_v, &mut b_int_v, iter);

        iter += 1;
    }
    // alternative: for loop in range with rev
    iter = 4;
    while iter >= 0 {
        for chunk in bits[calc_index..(calc_index + 512)].chunks(8) {
            b_int_v[i] = load8(chunk);
        }
        calc_index = if rev == 0 {
            calc_index
        } else {
            calc_index - 1024
        };

        layer_in(&mut r_int_v, &mut b_int_v, iter);

        iter -= 1;
    }

    transpose::transpose(&mut r_int_h[0], r_int_v[0]);
    transpose::transpose(&mut r_int_h[1], r_int_v[1]);

    iter = 6;
    while iter >= 0 {
        for chunk in bits[calc_index..(calc_index + 512)].chunks(8) {
            b_int_v[i] = load8(chunk);
        }
        calc_index = if rev == 0 {
            calc_index
        } else {
            calc_index - 1024
        };

        transpose::transpose(&mut b_int_h, b_int_v);

        layer_ex(&mut r_int_h[0], &mut b_int_h, iter);

        iter -= 1;
    }

    transpose::transpose(&mut r_int_v[0], r_int_h[0]);
    transpose::transpose(&mut r_int_v[1], r_int_h[1]);

    for chunk in r.chunks_mut(16) {
        let (subchunk1, subchunk2) = chunk.split_at_mut(8);
        store8(subchunk1, r_int_v[0][i]);
        store8(subchunk2, r_int_v[1][i]);
    }
}

// todo unit testing
