use crate::{
    gf::Gf,
    params::GFBITS,
    params::SYS_N,
    transpose,
    util::{bitrev, load8, store8},
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
// attempt maybe iterators
// for item in 2darray.iter().flatten() { … }
// or try https://docs.rs/bytemuck/1.7.2/bytemuck/ crate
fn layer_ex(data: &mut [[u64; 64]; 2], bits: &mut [u64], lgs: usize) {
    let (mut i, mut j, mut s): (usize, usize, usize) = (0, 0, 0);
    let mut d: u64;
    let mut index = 0;
    let mut index2 = 32;

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
            d &= bits[index2];
            index2 += 1;

            data[1][j + 0] ^= d;
            data[1][j + s] ^= d;

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
    let mut i: usize = 0;
    for chunk in r.chunks_mut(16) {
        let (subchunk1, subchunk2) = chunk.split_at_mut(8);
        r_int_v[1][i] = load8(subchunk1);
        r_int_v[0][i] = load8(subchunk2);
        i += 1;
    }

    transpose::transpose(&mut r_int_h[0], r_int_v[0]);
    transpose::transpose(&mut r_int_h[1], r_int_v[1]);

    let mut iter = 0;
    while iter <= 5 {
        i = 0;
        for chunk in bits[calc_index..(calc_index + 512)].chunks(8) {
            b_int_v[i] = load8(chunk);
            i += 1;
        }

        calc_index = if rev == 0 {
            calc_index + 512
        } else {
            calc_index - 1024
        };

        transpose::transpose(&mut b_int_h, b_int_v);

        layer_ex(&mut r_int_h, &mut b_int_h, iter);

        iter += 1;
    }

    transpose::transpose(&mut r_int_v[0], r_int_h[0]);
    transpose::transpose(&mut r_int_v[1], r_int_h[1]);

    let mut iter: usize = 0;
    while iter <= 5 {
        i = 0;
        for chunk in bits[calc_index..(calc_index + 512)].chunks(8) {
            b_int_v[i] = load8(chunk);
            i += 1;
        }
        calc_index = if rev == 0 {
            calc_index + 512
        } else {
            calc_index - 1024
        };

        layer_in(&mut r_int_v, &mut b_int_v, iter);

        iter += 1;
    }

    for iter in (0..=4).rev() {
        i = 0;
        for chunk in bits[calc_index..(calc_index + 512)].chunks(8) {
            b_int_v[i] = load8(chunk);
            i += 1;
        }
        calc_index = if rev == 0 {
            calc_index + 512
        } else {
            calc_index - 1024
        };

        layer_in(&mut r_int_v, &mut b_int_v, iter);
    }

    transpose::transpose(&mut r_int_h[0], r_int_v[0]);
    transpose::transpose(&mut r_int_h[1], r_int_v[1]);

    for iter in (0..=5).rev() {
        i = 0;
        for chunk in bits[calc_index..(calc_index + 512)].chunks(8) {
            b_int_v[i] = load8(chunk);
            i += 1;
        }
        calc_index = if rev == 0 {
            calc_index + 512
        } else {
            calc_index - 1024
        };

        transpose::transpose(&mut b_int_h, b_int_v);

        layer_ex(&mut r_int_h, &mut b_int_h, iter);
    }

    transpose::transpose(&mut r_int_v[0], r_int_h[0]);
    transpose::transpose(&mut r_int_v[1], r_int_h[1]);

    i = 0;
    for chunk in r.chunks_mut(16) {
        let (subchunk1, subchunk2) = chunk.split_at_mut(8);
        store8(subchunk1, r_int_v[0][i]);
        store8(subchunk2, r_int_v[1][i]);
        i += 1;
    }
}

#[test]
fn test_apply_benes() {
    // Basic testcase
    let mut L = [31u8; (1 << GFBITS) / 8];
    let mut bits = [0u8; 14160];
    bits[0] = 255;

    let mut compare_array = [31u8; (1 << GFBITS) / 8];
    compare_array[0] = 47;
    compare_array[1] = 47;

    apply_benes(&mut L, &bits, 0);

    assert_eq!(L, compare_array);

    /*for i in 0..L.len() {
        println!("i:{} res:{}", i, L[i]);
        if i > 40 {
            break;
        }
    }*/
}

pub fn support_gen(s: &mut [Gf; SYS_N], c: &[u8; 14160]) {
    let mut a: Gf;
    let (mut i, mut j): (usize, usize);
    let mut L = [[0u8; (1 << GFBITS) / 8]; GFBITS];

    i = 0;
    while i < (1 << GFBITS) {
        a = bitrev(i as Gf);
        for j in 0..GFBITS {
            L[j][i / 8] |= (((a >> j) & 1) << (i % 8)) as u8;
        }
        i += 1;
    }

    for j in 0..GFBITS {
        apply_benes(&mut L[j], c, 0);
    }

    for i in 0..SYS_N {
        s[i] = 0;
        for j in (0..=(GFBITS - 1)).rev() {
            s[i] <<= 1;
            s[i] |= ((L[j][i / 8] >> (i % 8)) & 1) as u16;
        }
    }
}
