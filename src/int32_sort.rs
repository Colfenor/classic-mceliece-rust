use rand::Rng;

const fn int32_MINMAX(mut a: i32, mut b: i32) -> (i32, i32) {
    let mut ab: i32 = b ^ a;
    let mut c: i32 = (!b & a) | ((!b | a) & (b.wrapping_sub(a)));
    c ^= ab & (c ^ b);
    c >>= 31;
    c &= ab;
    a ^= c;
    b ^= c;

    (a, b)
}

fn int32_sort(x: &mut [i32], n: usize) {
    let (mut top, mut p, mut q, mut r, mut i): (usize, usize, usize, usize, usize);

    if n < 2 {
        return;
    }
    top = 1;
    while top < n - top {
        top += top;
    }

    p = top;
    while p > 0 {
        i = 0;
        while i < n - p {
            if (i & p) == 0 {
                let (tmp_xi, tmp_xip) = int32_MINMAX(x[i], x[i + p]);
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
                        let (tmp_a, tmp_xir) = int32_MINMAX(a, x[i + r]);
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

fn gen_random_i32() -> i32 {
    rand::thread_rng().gen::<i32>()
}

#[test]
fn test_int32_MINMAX() {
    // basic test-case
    let x: i32 = 45;
    let y: i32 = -17;

    // first parameter should become min
    // second parameter should become max,
    let (x, y) = int32_MINMAX(x, y);

    assert_eq!(x, -17);
    assert_eq!(y, 45);

    //max value testcase
    let x: i32 = i32::MAX;
    let y: i32 = 2;

    let (x, y) = int32_MINMAX(x, y);

    assert_eq!(x, 2);
    assert_eq!(y, 2147483647);

    //min, max
    let x: i32 = i32::MAX;
    let y: i32 = i32::MIN;

    let (x, y) = int32_MINMAX(x, y);

    assert_eq!(x, -2147483648);
    assert_eq!(y, 2147483647);

    for i in 0..=40 {
        let x: i32 = gen_random_i32();
        let y: i32 = gen_random_i32();

        let (x, y) = int32_MINMAX(x, y);

        if x > y {
            println!(
                "erroneous behaviour with inputs: x: 0x{:016X}i32 y: 0x{:016X}i32",
                x, y
            );
        }
    }
}
