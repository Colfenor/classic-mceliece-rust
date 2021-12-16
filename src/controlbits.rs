use crate::int32_sort::int32_sort;
use crate::{int32_sort, params::GFBITS};

/* This file is for implementing the Nassimi-Sahni algorithm */
/* See David Nassimi, Sartaj Sahni "Parallel algorithms to set up the Benes permutationnetwork" */
/* See also https://cr.yp.to/papers/controlbits-20200923.pdf */

/* input: p, an array of int16 */
/* input: n, length of p */
/* input: s, meaning that stride-2^s cswaps are performed */
/* input: cb, the control bits */
/* output: the result of apply the control bits to p */

// cb size 8192
pub fn layer(p: &mut [i16], cb: &[u8], s: i32, n: i32) {
    let stride = 1 << s;
    let mut index = 0;
    let (mut d, mut m): (i16, i16) = (0, 0);

    for i in (0..n as usize).step_by(stride * 2) {
        for j in 0..stride {
            d = (p[(i + j) as usize] ^ p[(i + j + stride) as usize]) as i16;
            m = ((cb[index >> 3] >> (index & 7)) & 1) as i16;
            m = -m;
            d &= m;
            p[(i + j) as usize] ^= d as i16;
            p[(i + j + stride) as usize] ^= d as i16;
            index += 1;
        }
    }
}

// maybe slice indexing from destination
// dst[0..src.len()].clone_from_slice(&src)

// method for correct writing values to array q
// which is actually temp xD

/*
let temp: &[Cell<T>]= Cell::from_mut(temp).as_slice_of_cells();
let A = temp;
let B = &temp[n as usize..];
let q = &temp[(n + n / 4) as usize..];
*/

pub fn cbrecursion(
    out: &mut [u8],
    mut pos: i64,
    step: i64,
    pi: &mut [i16],
    w: i64,
    n: i64,
    temp: &mut [i32; 2 * (1 << GFBITS)],
) {
    assert_eq!(n, 1 << GFBITS);

    if w == 1 {
        out[(pos >> 3) as usize] ^= (pi[0] << (pos & 7)) as u8;
        return;
    }

    for x in 0..n as usize {
        temp[x] = ((pi[x] ^ 1).overflowing_shl(16).0 | pi[x ^ 1]) as i32;
    }

    int32_sort(temp, n);

    let mut Ax = 0;
    let mut px = 0;
    let mut cx = 0;

    for x in 0..n as usize {
        Ax = temp[x];
        px = Ax & 0xffff;
        cx = px;
        if x < cx as usize {
            cx = x as i32;
        }
        temp[n as usize + x] = (px << 16) | cx;
    }

    for x in 0..n as usize {
        temp[x] = (temp[x] << 16) | x as i32;
    }
    int32_sort(temp, n);

    let mut ppcpx = 0;
    let mut ppcx = 0;
    let mut cpx = 0;

    if w <= 10 {
        for x in 0..n as usize {
            temp[n as usize + x] = ((temp[x] & 0xffff) << 10) | (temp[x] & 0x3ff);
        }

        for i in 1..w - 1 {
            for x in 0..n as usize {
                temp[x] = ((temp[n as usize + x] & !0x3ff) << 6) | x as i32;
            }
            int32_sort(temp, n);

            for x in 0..n as usize {
                temp[x] = (temp[x] << 20) | temp[n as usize + x];
            }
            int32_sort(temp, n);

            for x in 0..n as usize {
                ppcpx = temp[x] & 0xfffff;
                ppcx = (temp[x] & 0xffc00) | (temp[n as usize + x] & 0x3ff);

                if ppcpx < ppcx {
                    ppcx = ppcpx;
                }
                temp[n as usize + x] = ppcx;
            }
        }

        for x in 0..n as usize {
            temp[n as usize + x] &= 0x3ff;
        }
    } else {
        for x in 0..n as usize {
            temp[n as usize + x] = (temp[x] << 16) | (temp[n as usize + x] & 0xffff);
        }

        for i in 1..w - 1 {
            for x in 0..n as usize {
                temp[x] = (temp[n as usize + x] & !0xffff) | x as i32;
            }
            int32_sort(temp, n);

            for x in 0..n as usize {
                temp[x] = (temp[x] << 16) | (temp[n as usize + x] & 0xffff);
            }

            if i < w - 2 {
                for x in 0..n as usize {
                    temp[n as usize + x] = (temp[x] & !0xffff) | (temp[n as usize + x] >> 16);
                }
                int32_sort(&mut temp[n as usize..], n);

                for x in 0..n as usize {
                    temp[n as usize + x] = (temp[n as usize + x] << 16) | (temp[x] & 0xffff);
                }
            }
            int32_sort(temp, n);

            for x in 0..n as usize {
                cpx = (temp[n as usize + x] & !0xffff) | (temp[x] & 0xffff);
                if cpx < temp[n as usize + x] {
                    temp[n as usize + x] = cpx;
                }
            }
        }
        for x in 0..n as usize {
            temp[n as usize + x] &= 0xffff;
        }
    }

    for x in 0..n as usize {
        temp[x] = (pi[x].overflowing_shl(16).0 + x as i16) as i32;
    }
    int32_sort(temp, n);

    let mut x: usize = 0;
    let mut fj: i32 = 0;
    let mut Fx: i32 = 0;
    let mut Fx1 = 0;

    for j in 0..(n / 2) as usize {
        x = 2 * j;
        fj = temp[n as usize + x] & 1; /* f[j] */
        Fx = x as i32 + fj; /* F[x] */
        Fx1 = Fx ^ 1; /* F[x+1] */

        out[(pos >> 3) as usize] ^= (fj << (pos & 7)) as u8;
        pos += step;

        temp[n as usize + x] = (temp[x] << 16) | Fx;
        temp[n as usize + x + 1] = (temp[x + 1] << 16) | Fx1;
    }
    int32_sort(&mut temp[n as usize..], n);

    pos += (2 * w - 3) * step * (n / 2);

    let mut y: usize = 0;
    let mut lk = 0;
    let mut Ly = 0;
    let mut Ly1 = 0;

    for k in 0..(n / 2) as usize {
        y = 2 * k;
        lk = temp[n as usize + y] & 1; /* l[k] */
        Ly = y as i32 + lk; /* L[y] */
        Ly1 = Ly ^ 1; /* L[y+1] */

        out[(pos >> 3) as usize] ^= (lk << (pos & 7)) as u8;
        pos += step;

        temp[y] = (Ly << 16) | (temp[n as usize + y] & 0xffff);
        temp[y + 1] = (Ly1 << 16) | (temp[n as usize + y + 1] & 0xffff);
    }
    int32_sort(temp, n);

    pos -= (2 * w - 2) * step * (n / 2);

    for j in 0..(n / 4) as usize {
        //q[j].set(((A[j]  & 0xffff) >> 1) + (((A[j+2]  & 0xffff)) >> 1) << 16);

        //q[j + (n / 2) as usize] = ((A[j + 1]  & 0xffff) >> 1) as i16;
    }

    //cbrecursion(out, pos, step * 2, &mut q, w - 1, n / 2, temp);
    //cbrecursion(out, pos + step, step * 2, &mut new_q, w - 1, n / 2, temp);*/
}

// params
// out = sk secret key bits
// n = 1 << GFBITS, 8192
// w = GFBITS, 13
// pi[8192]
pub fn controlbitsfrompermutation(out: &mut [u8], pi: &mut [i16], w: i64, n: i64) {
    let mut temp = [0i32; 2 * (1 << GFBITS)];
    let mut diff: i16 = 0;
    let mut counter: i32;

    let mut pi_test = [0i16; 1 << GFBITS];
    //let mut ptr = out.to_vec();

    /*
    calc,
    (((2*w-1)*n/2)+7)/8 = 12800.875
    14120 - 12800 = 1320

    8192 >> 4 = 512, stepsize
    */
    out.fill(0);
    let mut ptr = out; // moving value to ptr
    let mut first_itr = true;

    loop {
        if first_itr == true {
            first_itr = false;
        } else {
            ptr.fill(0);
        }

        cbrecursion(ptr, 0, 1, pi, w, n, &mut temp);

        //let mut ptr = out; // moving value to ptr
        for i in 0..w as usize {
            layer(&mut pi_test, ptr, i as i32, n as i32);
            ptr = &mut ptr[(n >> 4) as usize..];
        }

        for i in (0..w - 2).rev() {
            layer(&mut pi_test, ptr, i as i32, n as i32);
            ptr = &mut ptr[(n >> 4) as usize..];
        }

        for i in 0..n as usize {
            diff |= pi[i] ^ pi_test[i];
        }

        if diff == 0 {
            break;
        }
    }
}

#[test]
pub fn test_controlbitsfrompermutation() {
    use crate::controlbits_arrays::PI_INPUT;

    let mut skp = [0u8; 13824];

    let mut test_pi = PI_INPUT.to_vec();

    controlbitsfrompermutation(&mut skp, &mut test_pi, GFBITS as i64, 1 << GFBITS as i64);

    for i in 0..13824 {
        println!("i:{}, skp:{}", i, skp[i]);
    }
}
