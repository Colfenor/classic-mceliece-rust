//! Matrix transpose implementation

/// Compute transposition of `input` and store it in `output`
#[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
pub(crate) fn transpose(output: &mut [u64; 64], input: [u64; 64]) {
    let masks: [[u64; 2]; 6] = [
        [0x5555555555555555, 0xAAAAAAAAAAAAAAAA],
        [0x3333333333333333, 0xCCCCCCCCCCCCCCCC],
        [0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0],
        [0x00FF00FF00FF00FF, 0xFF00FF00FF00FF00],
        [0x0000FFFF0000FFFF, 0xFFFF0000FFFF0000],
        [0x00000000FFFFFFFF, 0xFFFFFFFF00000000],
    ];

    *output = input;

    for d in (0..=5).rev() {
        let s = 1 << d;

        for i in (0..64).step_by(s * 2) {
            for j in i..i + s {
                let x = (output[j] & masks[d][0]) | ((output[j + s] & masks[d][0]) << s);
                let y = ((output[j] & masks[d][1]) >> s) | (output[j + s] & masks[d][1]);

                output[j + 0] = x;
                output[j + s] = y;
            }
        }
    }
}

/// Take a 64×64 matrix over GF(2).
/// Compute the transpose of `arg` and return it in `arg`
///
/// Unlike the C implementation, this function works in-place.
/// The C implementation uses the function only in a way such that
/// input argument == output argument. Because we cannot create a
/// shared and mutable reference simultaneously, we can only generate
/// one argument.
#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
pub(crate) fn transpose_64x64_inplace(arg: &mut [u64; 64]) {
    let masks = [
        [0x5555555555555555u64, 0xAAAAAAAAAAAAAAAAu64],
        [0x3333333333333333, 0xCCCCCCCCCCCCCCCC],
        [0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0],
        [0x00FF00FF00FF00FF, 0xFF00FF00FF00FF00],
        [0x0000FFFF0000FFFF, 0xFFFF0000FFFF0000],
        [0x00000000FFFFFFFF, 0xFFFFFFFF00000000],
    ];

    for d in (0..6).rev() {
        let s = 1 << d;
        let mut i = 0;
        while i < 64 {
            for j in i..(i + s) {
                let x: u64 = (arg[j] & masks[d][0]) | ((arg[j + s] & masks[d][0]) << s);
                let y: u64 = ((arg[j] & masks[d][1]) >> s) | (arg[j + s] & masks[d][1]);

                arg[j] = x;
                arg[j + s] = y;
            }
            i += s * 2;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestMatrix {
        input: [u64; 64],
        output: [u64; 64],
    }

    #[test]
    fn test_transpose() {
        let mut testcases: [TestMatrix; 2] = [
            TestMatrix {
                input: [0u64; 64],
                output: [0u64; 64],
            },
            TestMatrix {
                input: [0u64; 64],
                output: [0u64; 64],
            },
        ];

        testcases[0] = TestMatrix {
            input: [
                0x0000000000000000u64,
                0x0000000000000001u64,
                0x0000000000000002u64,
                0x0000000000000003u64,
                0x0000000000000004u64,
                0x0000000000000005u64,
                0x0000000000000006u64,
                0x0000000000000007u64,
                0x0000000000000008u64,
                0x0000000000000009u64,
                0x000000000000000Au64,
                0x000000000000000Bu64,
                0x000000000000000Cu64,
                0x000000000000000Du64,
                0x000000000000000Eu64,
                0x000000000000000Fu64,
                0x0000000000000010u64,
                0x0000000000000011u64,
                0x0000000000000012u64,
                0x0000000000000013u64,
                0x0000000000000014u64,
                0x0000000000000015u64,
                0x0000000000000016u64,
                0x0000000000000017u64,
                0x0000000000000018u64,
                0x0000000000000019u64,
                0x000000000000001Au64,
                0x000000000000001Bu64,
                0x000000000000001Cu64,
                0x000000000000001Du64,
                0x000000000000001Eu64,
                0x000000000000001Fu64,
                0x0000000000000020u64,
                0x0000000000000021u64,
                0x0000000000000022u64,
                0x0000000000000023u64,
                0x0000000000000024u64,
                0x0000000000000025u64,
                0x0000000000000026u64,
                0x0000000000000027u64,
                0x0000000000000028u64,
                0x0000000000000029u64,
                0x000000000000002Au64,
                0x000000000000002Bu64,
                0x000000000000002Cu64,
                0x000000000000002Du64,
                0x000000000000002Eu64,
                0x000000000000002Fu64,
                0x0000000000000030u64,
                0x0000000000000031u64,
                0x0000000000000032u64,
                0x0000000000000033u64,
                0x0000000000000034u64,
                0x0000000000000035u64,
                0x0000000000000036u64,
                0x0000000000000037u64,
                0x0000000000000038u64,
                0x0000000000000039u64,
                0x000000000000003Au64,
                0x000000000000003Bu64,
                0x000000000000003Cu64,
                0x000000000000003Du64,
                0x000000000000003Eu64,
                0x000000000000003Fu64,
            ],
            output: [
                0xAAAAAAAAAAAAAAAAu64,
                0xCCCCCCCCCCCCCCCCu64,
                0xF0F0F0F0F0F0F0F0u64,
                0xFF00FF00FF00FF00u64,
                0xFFFF0000FFFF0000u64,
                0xFFFFFFFF00000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
            ],
        };
        testcases[1] = TestMatrix {
            input: [
                0x000000000000000Au64,
                0x000000000000000Bu64,
                0x000000000000000Cu64,
                0x000000000000000Du64,
                0x000000000000000Eu64,
                0x000000000000000Fu64,
                0x0000000000000010u64,
                0x0000000000000011u64,
                0x0000000000000012u64,
                0x0000000000000013u64,
                0x0000000000000014u64,
                0x0000000000000015u64,
                0x0000000000000016u64,
                0x0000000000000017u64,
                0x0000000000000018u64,
                0x0000000000000019u64,
                0x000000000000001Au64,
                0x000000000000001Bu64,
                0x000000000000001Cu64,
                0x000000000000001Du64,
                0x000000000000001Eu64,
                0x000000000000001Fu64,
                0x0000000000000020u64,
                0x0000000000000021u64,
                0x0000000000000022u64,
                0x0000000000000023u64,
                0x0000000000000024u64,
                0x0000000000000025u64,
                0x0000000000000026u64,
                0x0000000000000027u64,
                0x0000000000000028u64,
                0x0000000000000029u64,
                0x000000000000002Au64,
                0x000000000000002Bu64,
                0x000000000000002Cu64,
                0x000000000000002Du64,
                0x000000000000002Eu64,
                0x000000000000002Fu64,
                0x0000000000000030u64,
                0x0000000000000031u64,
                0x0000000000000032u64,
                0x0000000000000033u64,
                0x0000000000000034u64,
                0x0000000000000035u64,
                0x0000000000000036u64,
                0x0000000000000037u64,
                0x0000000000000038u64,
                0x0000000000000039u64,
                0x000000000000003Au64,
                0x000000000000003Bu64,
                0x000000000000003Cu64,
                0x000000000000003Du64,
                0x000000000000003Eu64,
                0x000000000000003Fu64,
                0x0000000000000040u64,
                0x0000000000000041u64,
                0x0000000000000042u64,
                0x0000000000000043u64,
                0x0000000000000044u64,
                0x0000000000000045u64,
                0x0000000000000046u64,
                0x0000000000000047u64,
                0x0000000000000048u64,
                0x0000000000000049u64,
            ],
            output: [
                0xAAAAAAAAAAAAAAAAu64,
                0x3333333333333333u64,
                0x3C3C3C3C3C3C3C3Cu64,
                0xC03FC03FC03FC03Fu64,
                0x003FFFC0003FFFC0u64,
                0x003FFFFFFFC00000u64,
                0xFFC0000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
            ],
        };

        for testcase in testcases {
            #[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
            {
                let mut test_output: [u64; 64] = [0; 64];
                transpose(&mut test_output, testcase.input);
                assert_eq!(test_output, testcase.output);
            }

            #[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
            {
                let mut data = testcase.input;
                transpose_64x64_inplace(&mut data);
                assert_eq!(data, testcase.output);
            }
        }
    }
}
