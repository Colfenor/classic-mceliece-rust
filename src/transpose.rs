pub fn transpose(output: &mut [u64; 64], input: [u64; 64]) {
    assert!(
        output.len() == 64 && input.len() == 64,
        "Error, array-length has to be 64."
    );

    let (mut x, mut y): (u64, u64);

    let masks: [[u64; 2]; 6] = [
        [0x5555555555555555, 0xAAAAAAAAAAAAAAAA],
        [0x3333333333333333, 0xCCCCCCCCCCCCCCCC],
        [0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0],
        [0x00FF00FF00FF00FF, 0xFF00FF00FF00FF00],
        [0x0000FFFF0000FFFF, 0xFFFF0000FFFF0000],
        [0x00000000FFFFFFFF, 0xFFFFFFFF00000000],
    ];
    //println!("{:X}", masks[0][0] as i32);
    //println!("{:X}", masks[0][1] as i32);
    //println!("{:X}", masks[4][0] as i32);

    let (mut i, mut j, mut s): (usize, usize, usize);

    for h in 0..63 {
        output[h] = input[h];
    }

    for d in (0..=5).rev() {
        s = 1 << d;

        i = 0;
        while i < 64 {
            j = i;
            while j < i + s {
                x = (output[j] & masks[d][0]) | ((output[j + s] & masks[d][0]) << s);
                y = ((output[j] & masks[d][1]) >> s) | (output[j + s] & masks[d][1]);

                output[j + 0] = x;
                output[j + s] = y;

                j += 1;
            }
            i += s * 2;
        }
    }
}
