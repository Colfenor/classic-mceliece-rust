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

fn gen_random_u64() -> u64 {
    rand::thread_rng().gen::<u64>()
}

#[test]
fn test_uint64_MINMAX() {
    // basic test-case
    let mut x: u64 = 42;
    let mut y: u64 = 10;

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
        let mut x: u64 = gen_random_u64();
        let mut y: u64 = gen_random_u64();

        let (x, y) = uint64_MINMAX(x, y);

        if (x > y) {
            println!(
                "errornous behaviour with inputs: x: 0x{:016X}u64 y: 0x{:016X}u64",
                x, y
            );
        }
    }
}
