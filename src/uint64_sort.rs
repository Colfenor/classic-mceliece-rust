use rand::Rng;
// side-channel effective overflow check of variable c
// source: book Hacker's Delight 2–13 Overflow Detection,
// Section Unsigned Add/Subtract p. 40
// let (_, c) = b.overflowing_sub(a); shouldn't be used, because this
// will create a branch on some compilers

const fn uint64_MINMAX(mut a: u64, mut b: u64) -> (u64, u64) {
    let d: u64 = (!b & a) | ((!b | a) & (b.wrapping_sub(a)));
    let mut c: u64 = d >> 63;
    c = 0u64.wrapping_sub(c);
    c &= a ^ b;
    a ^= c;
    b ^= c;

    (a, b)
}

pub fn uint64_sort(x: &mut [u64], n: usize) {
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
                let (tmp_xi, tmp_xip) = uint64_MINMAX(x[i], x[i + p]);
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
                        let (tmp_a, tmp_xir) = uint64_MINMAX(a, x[i + r]);
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

// Unit tests
fn gen_random_u64() -> u64 {
    rand::thread_rng().gen::<u64>()
}

#[test]
fn test_uint64_MINMAX() {
    // basic test-case
    let x: u64 = 42;
    let y: u64 = 10;

    // first parameter should become min
    // second parameter should become max,
    let (x, y) = uint64_MINMAX(x, y);

    //println!("x is {}", x);
    //println!("y is {}", y);

    assert_eq!(x, 10);
    assert_eq!(y, 42);

    // max value test-case
    let x: u64 = 0xffffffffffffffff;
    let y: u64 = 1;

    let (x, y) = uint64_MINMAX(x, y);

    assert_eq!(x, 1);
    assert_eq!(y, 0xffffffffffffffff);

    // generator test case
    for i in 0..=40 {
        let x: u64 = gen_random_u64();
        let y: u64 = gen_random_u64();

        let (x, y) = uint64_MINMAX(x, y);

        if x > y {
            println!(
                "erroneous behaviour with inputs: x: 0x{:016X}u64 y: 0x{:016X}u64",
                x, y
            );
        }
    }
}

#[test]
fn test_uint64_sort() {
    let mut array: [u64; 64] = [0; 64];

    for i in 0..array.len() {
        array[i] = gen_random_u64();
        //println!("{}", array[i]);
    }

    uint64_sort(&mut array, 64);

    for i in 0..array.len() {
        //println!("{}", array[i]);
        if i >= 1 {
            assert_eq!(array[i] > array[i - 1], true);
        }
    }
}
