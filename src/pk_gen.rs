use crate::{
    api::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES},
    gf::{gf_inv, gf_mul},
    params::{GFBITS, GFMASK, PK_NROWS, PK_ROW_BYTES, SYS_N, SYS_T},
    pk_gen_arrays::{PERM_INPUT, PK_COMPARE},
    root::root,
    uint64_sort::uint64_sort,
    util::{bitrev, load8, load_gf, store8},
};

/* return number of trailing zeros of the non-zero input in */
fn ctz(input: u64) -> i32 {
    let (mut b, mut m, mut r): (i32, i32, i32) = (0, 0, 0);

    for i in 0..64 {
        b = ((input >> i) & 1) as i32;
        m |= b;
        r += (m ^ 1) & (b ^ 1);
    }
    r
}

fn same_mask(x: u16, y: u16) -> u64 {
    let mut mask = 0u64;

    mask = (x ^ y) as u64;
    mask = mask.wrapping_sub(1);
    mask >>= 63;
    mask = 0u64.wrapping_sub(mask);
    // return value either 0 or u64::MAX

    mask
}

//params
//	unsigned char mat[ PK_NROWS ][ SYS_N/8 ];
// 	int16_t pi[ 1 << GFBITS ];
// 	uint64_t pivots;

fn mov_columns(
    mat: &mut [[u8; SYS_N / 8]; PK_NROWS],
    pi: &mut [i16; 1 << GFBITS],
    pivots: &mut u64,
) -> i32 {
    let mut buf = [0u64; 64];
    let mut ctz_list = [0u64; 32];
    let mut one: u64 = 1;
    let mut t = 0u64;
    let mut d = 0u64;

    let mut mask = 0u64;

    let mut s = 0i32;
    let mut row = PK_NROWS - 32; // 1664 - 32 = 1632
    let mut block_idx = row / 8; // 1632 / 8 = 204...
    let mut mat_row: [u8; SYS_N / 8];

    for i in 0..32 {
        mat_row = mat[row + i];
        buf[i] = load8(&mat_row[block_idx..block_idx + 8]);
    }

    // compute the column indices of pivots by Gaussian elimination.
    // the indices are stored in ctz_list

    *pivots = 0;
    let mut j = 0;
    for i in 0..32 {
        t = buf[i];
        for j in i + 1..32 {
            t |= buf[j];
        }
        //println!("i:{}, t:{}", i, t);

        if t == 0 {
            return -1; // return if buf is not full rank
        }

        ctz_list[i] = ctz(t) as u64;
        s = ctz_list[i] as i32;

        *pivots |= one << s;

        for j in i + 1..32 {
            mask = (buf[i] >> s) & 1;
            mask = mask.wrapping_sub(1);
            buf[i] ^= buf[j] & mask;
        }

        for j in i + 1..32 {
            mask = (buf[j] >> s) & 1;
            mask = 0u64.wrapping_sub(mask);
            buf[j] ^= buf[i] & mask;
        }
    }

    // updating permutation
    for j in 0..32 {
        for k in j + 1..64 {
            d = (pi[row + j] ^ pi[row + k]) as u64;
            d &= same_mask(k as u16, ctz_list[j] as u16);
            pi[row + j] ^= d as i16;
            pi[row + k] ^= d as i16;
        }
    }

    // moving columns of mat according to the column indices of pivots
    for i in 0..PK_NROWS {
        //mat_row = mat[i]; NEVERRRRR DO THIS !!!!!
        t = load8(&mat[i][block_idx..block_idx + 8]);

        for j in 0..32 {
            d = t >> j;
            d ^= t >> ctz_list[j];
            d &= 1;

            t ^= d << ctz_list[j];
            t ^= d << j;
        }
        //println!("i:{}, t:{:x}", i, t);
        store8(&mut mat[i][block_idx..block_idx + 8], t);
        //println!("i:{}, mat:{}", i, mat[i][block_idx]);
    }

    return 0;
}

pub fn print_mat(mat: &[[u8; SYS_N / 8]; PK_NROWS]) {
    for i in 0..PK_NROWS {
        for j in 0..SYS_N / 8 {
            println!("mat[{}][{}]:{}", i, j, mat[i][j]);
        }
    }
}

// params
//unsigned char* pk bytes 1357824
//unsigned char* sk bytes 14120 - SYS_T*2 = 13864
// u32 perm 1 << GFBITS
// i16 pi 1 << GFBITS

//sk: &mut [u8; CRYPTO_SECRETKEYBYTES - SYS_T * 2],
pub fn pk_gen(
    pk: &mut [u8],
    sk: &mut [u8],
    perm: &mut [u32],
    pi: &mut [i16; 1 << GFBITS],
    pivots: &mut u64,
) -> i32 {
    let mut row = 0;

    let mut buf = [0u64; 1 << GFBITS];
    let mut mat = [[0u8; SYS_N / 8]; PK_NROWS];
    let mut mask = 0u8;
    let mut b = 0u8;

    let mut g = [0u16; SYS_T + 1];
    let mut L = [0u16; SYS_N];
    let mut inv = [0u16; SYS_N];

    g[SYS_T] = 1;

    let mut i = 0;
    for chunk in sk.chunks_mut(2) {
        g[i] = load_gf(chunk);
        i += 1;
        if i == SYS_T - 1 {
            break;
        }
    }

    for i in 0..(1 << GFBITS) {
        buf[i] = perm[i] as u64;
        buf[i] <<= 31;
        buf[i] |= i as u64;
    }

    uint64_sort(&mut buf, 1 << GFBITS);

    for i in 1..(1 << GFBITS) {
        if buf[i - 1] >> 31 == buf[i] >> 31 {
            return -1;
        }
    }

    for i in 0..(1 << GFBITS) {
        pi[i] = (buf[i] & GFMASK as u64) as i16;
    }

    // TODO check casting for errors
    for i in 0..SYS_N {
        L[i] = bitrev(pi[i] as u16);
    }

    root(&mut inv, &mut g, &mut L);

    for i in 0..SYS_N {
        inv[i] = gf_inv(inv[i]);
    }

    for i in 0..SYS_T {
        for j in (0..SYS_N).step_by(8) {
            for k in 0..GFBITS {
                b = ((inv[j + 7] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 6] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 5] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 4] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 3] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 2] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 1] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 0] >> k) & 1) as u8;

                mat[i * GFBITS + k][j / 8] = b;
                //println!("j:{}, mat:{}", j, mat[i * GFBITS + k][j / 8]);
            }
        }
        for j in 0..SYS_N {
            inv[j] = gf_mul(inv[j], L[j]);
        }
    }

    // gaussian elimination
    for i in 0..(PK_NROWS + 7) / 8 {
        for j in 0..8 {
            row = i * 8 + j;

            if row >= PK_NROWS {
                break;
            }

            if row == PK_NROWS - 32 {
                if mov_columns(&mut mat, pi, pivots) != 0 {
                    return -1;
                }
            }

            for k in (row + 1)..PK_NROWS {
                mask = mat[row][i] ^ mat[k][i];
                mask >>= j;
                mask &= 1;
                mask = 0u8.wrapping_sub(mask);

                for c in 0..SYS_N / 8 {
                    mat[row][c] ^= mat[k][c] & mask;
                }
            }

            if ((mat[row][i] >> j) & 1) == 0 {
                return -1;
            }

            for k in 0..PK_NROWS {
                if k != row {
                    mask = mat[k][i] >> j;
                    mask &= 1;
                    mask = 0u8.wrapping_sub(mask);

                    for c in 0..(SYS_N / 8) {
                        mat[k][c] ^= mat[row][c] & mask;
                    }
                }
            }
        }
    }

    //unsigned char mat[ PK_NROWS ][ SYS_N/8 ];
    for i in 0..PK_NROWS {
        for j in 0..PK_ROW_BYTES {
            pk[i * PK_ROW_BYTES + j] = mat[i][PK_NROWS / 8 + j];
            //println!("pk:{}", pk[i * PK_ROW_BYTES + j]);
        }
    }
    return 0;
}

/*#[test]
pub fn test_mov_columns() {
    let mut pivots = 0u64;
    let mut pi = [0i16; 1 << GFBITS];
    //let mut perm = [0i32, 1 << GFBITS];
    let mut mat = [[0u8; SYS_N / 8]; PK_NROWS];

    for i in 0..PK_NROWS {
        for j in 0..(SYS_N / 8) {
            mat[i][j] = i as u8;
        }
    }
    mov_columns(&mut mat, &mut pi, &mut pivots);
}*/

#[test]
pub fn test_pk_gen() {
    let mut test_perm = PERM_INPUT.to_vec();
    assert_eq!(test_perm.len(), 1 << GFBITS);

    let mut sk: [u8; SYS_T] = [
        199, 216, 123, 163, 126, 230, 196, 18, 117, 1, 41, 51, 200, 109, 66, 233, 33, 107, 214, 76,
        177, 56, 124, 190, 64, 198, 125, 205, 220, 113, 133, 213, 72, 4, 89, 57, 127, 162, 245,
        223, 83, 11, 34, 11, 74, 69, 23, 140, 117, 16, 115, 109, 153, 135, 125, 9, 121, 90, 117,
        31, 99, 125, 190, 190, 64, 29, 87, 74, 123, 168, 123, 149, 57, 243, 111, 64, 238, 56, 169,
        86, 62, 234, 171, 88, 164, 51, 195, 223, 215, 88, 35, 232, 78, 104, 245, 198, 208, 78, 135,
        127, 13, 30, 239, 167, 182, 210, 40, 252, 162, 64, 120, 166, 216, 120, 160, 69, 181, 82,
        31, 242, 90, 27, 146, 6, 0, 52, 223, 41,
    ];

    let mut pivots = 0u64;
    let mut pi = [0i16; 1 << GFBITS];
    let mut pk = vec![0u8; CRYPTO_PUBLICKEYBYTES];
    //let mut perm = [0u32, 1 << GFBITS];

    pk_gen(&mut pk, &mut sk, &mut test_perm, &mut pi, &mut pivots);

    /*for i in 0..400 {
        println!("{}", pk[i]);
    }*/
    assert_eq!(pk, PK_COMPARE);
}
