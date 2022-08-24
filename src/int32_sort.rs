//! Sort an array of i32 elements in constant-time

/// If `a > b`, swap `a` and `b` in-place. Otherwise keep values.
/// Implements `(min(a, b), max(a, b))` in constant time.
const fn int32_minmax(mut a: i32, mut b: i32) -> (i32, i32) {
    let ab: i32 = b ^ a;
    let mut c: i32 = (!b & a) | ((!b | a) & (b.wrapping_sub(a)));
    c ^= ab & (c ^ b);
    c >>= 31;
    c &= ab;
    a ^= c;
    b ^= c;

    (a, b)
}

/// Sort a sequence of integers using a sorting network to achieve constant time.
/// To our understanding, this implements [djbsort](https://sorting.cr.yp.to/).
pub(crate) fn int32_sort(x: &mut [i32]) {
    let n = x.len();
    let (mut top, mut p, mut q, mut r, mut i): (usize, usize, usize, usize, usize);

    if n < 2 {
        return;
    }
    top = 1;
    #[allow(clippy::overflow_check_conditional)]
    while top < n - top {
        top += top;
    }

    p = top;
    while p > 0 {
        i = 0;
        while i < n - p {
            if (i & p) == 0 {
                let (tmp_xi, tmp_xip) = int32_minmax(x[i], x[i + p]);
                x[i] = tmp_xi;
                x[i + p] = tmp_xip;
            }
            i += 1;
        }
        i = 0;
        q = top;
        while q > p {
            while i < n - q {
                if (i & p) == 0 {
                    let mut a = x[i + p];
                    r = q;
                    while r > p {
                        let (tmp_a, tmp_xir) = int32_minmax(a, x[i + r]);
                        x[i + r] = tmp_xir;
                        a = tmp_a;
                        r >>= 1;
                    }
                    x[i + p] = a;
                }
                i += 1;
            }
            q >>= 1;
        }
        p >>= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    fn gen_random_i32() -> i32 {
        rand::thread_rng().gen::<i32>()
    }

    #[test]
    fn test_int32_minmax() {
        // basic test-case
        let x: i32 = 45;
        let y: i32 = -17;

        // first parameter should become min
        // second parameter should become max,
        let (x, y) = int32_minmax(x, y);

        assert_eq!(x, -17);
        assert_eq!(y, 45);

        //max value testcase
        let x: i32 = i32::MAX;
        let y: i32 = 2;

        let (x, y) = int32_minmax(x, y);

        assert_eq!(x, 2);
        assert_eq!(y, 2147483647);

        //min, max
        let x: i32 = i32::MAX;
        let y: i32 = i32::MIN;

        let (x, y) = int32_minmax(x, y);

        assert_eq!(x, -2147483648);
        assert_eq!(y, 2147483647);

        for _ in 0..=40 {
            let x: i32 = gen_random_i32();
            let y: i32 = gen_random_i32();

            let (x, y) = int32_minmax(x, y);

            if x > y {
                println!(
                    "erroneous behaviour with inputs: x: 0x{:016X}i32 y: 0x{:016X}i32",
                    x, y
                );
            }
        }
    }

    #[test]
    fn test_int32_sort() {
        let mut array: [i32; 64] = [0; 64];

        for i in 0..array.len() {
            array[i] = gen_random_i32();
            //println!("{}", array[i]);
        }

        int32_sort(&mut array[0..64]);

        for i in 0..array.len() {
            //println!("{}", array[i]);
            if i >= 1 {
                assert_eq!(array[i] > array[i - 1], true);
            }
        }
    }
}
