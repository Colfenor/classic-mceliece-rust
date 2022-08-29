//! Sort an array of u64 elements in constant-time

/// If `a > b`, swap `a` and `b` in-place. Otherwise keep values.
/// Implements `(min(a, b), max(a, b))` in constant time.
///
/// This differs from the C implementation, because the C implementation
/// only works for 63-bit integers.
///
/// Instead this implementation is based on
/// “side-channel effective overflow check of variable c”
/// from the book “Hacker's Delight” 2–13 Overflow Detection,
/// Section Unsigned Add/Subtract p. 40
const fn uint64_minmax(mut a: u64, mut b: u64) -> (u64, u64) {
    let d: u64 = (!b & a) | ((!b | a) & (b.wrapping_sub(a)));
    let mut c: u64 = d >> 63;
    c = 0u64.wrapping_sub(c);
    c &= a ^ b;
    a ^= c;
    b ^= c;

    (a, b)
}

/// Sort a sequence of integers using a sorting network to achieve constant time.
/// To our understanding, this implements [djbsort](https://sorting.cr.yp.to/).
pub(crate) fn uint64_sort<const N: usize>(x: &mut [u64; N]) {
    if N < 2 {
        return;
    }
    let mut top = 1;

    while top < N.wrapping_sub(top) {
        top += top;
    }

    let mut p = top;
    while p > 0 {
        for i in 0..(N - p) {
            if (i & p) == 0 {
                let (tmp_xi, tmp_xip) = uint64_minmax(x[i], x[i + p]);
                x[i] = tmp_xi;
                x[i + p] = tmp_xip;
            }
        }
        let mut q = top;
        while q > p {
            for i in 0..(N - q) {
                if (i & p) == 0 {
                    let mut a = x[i + p];
                    let mut r = q;
                    while r > p {
                        let (tmp_a, tmp_xir) = uint64_minmax(a, x[i + r]);
                        x[i + r] = tmp_xir;
                        a = tmp_a;
                        r >>= 1;
                    }
                    x[i + p] = a;
                }
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

    fn gen_random_u64() -> u64 {
        rand::thread_rng().gen::<u64>()
    }

    #[test]
    fn test_uint64_minmax() {
        // basic test-case
        let x: u64 = 42;
        let y: u64 = 10;

        // first parameter should become min
        // second parameter should become max,
        let (x, y) = uint64_minmax(x, y);

        //println!("x is {}", x);
        //println!("y is {}", y);

        assert_eq!(x, 10);
        assert_eq!(y, 42);

        // max value test-case
        let x: u64 = 0xffffffffffffffff;
        let y: u64 = 1;

        let (x, y) = uint64_minmax(x, y);

        assert_eq!(x, 1);
        assert_eq!(y, 0xffffffffffffffff);

        // generator test case
        for _ in 0..=40 {
            let x: u64 = gen_random_u64();
            let y: u64 = gen_random_u64();

            let (x, y) = uint64_minmax(x, y);

            if x > y {
                panic!(
                    "erroneous behaviour with inputs: x: 0x{:016X}u64 y: 0x{:016X}u64",
                    x, y
                );
            }
        }
    }

    #[test]
    fn test_uint64_sort_random_numbers() {
        let mut array: [u64; 64] = [0; 64];

        for a in array.iter_mut() {
            *a = gen_random_u64();
        }

        uint64_sort(&mut array);

        for i in 1..array.len() {
            assert!(array[i] >= array[i - 1]);
        }
    }
}
