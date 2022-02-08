use crate::gf::{gf_inv, gf_iszero, gf_mul, GF_mul, Gf};
use crate::params::SYS_T;

// out and f both arrays with SYS_T len

/* input: f, element in GF((2^m)^t) */
/* output: out, minimal polynomial of f */
/* return: 0 for success and -1 for failure */
pub fn genpoly_gen(out: &mut [Gf; SYS_T], f: &mut [Gf; SYS_T]) -> isize {
    let mut mat = [[0u16; SYS_T]; SYS_T + 1];
    let (mut mask, mut inv, mut t): (Gf, Gf, Gf) = (0, 0, 0);

    mat[0][0] = 1;

    for i in 1..SYS_T {
        mat[0][i] = 0;
    }

    for i in 0..SYS_T {
        mat[1][i] = f[i];
    }

    let mut j = 2;
    while j <= SYS_T {
        let (left, right) = mat.split_at_mut(j);
        GF_mul(&mut right[0], &mut left[j - 1], f);
        j += 1;
    }

    let mut k = 0;
    let mut c = 0;

    for j in 0..SYS_T {
        k = j + 1;
        while k < SYS_T {
            mask = gf_iszero(mat[j][j]);

            c = j;
            while c < SYS_T + 1 {
                mat[c][j] ^= mat[c][k] & mask;
                c += 1;
            }

            k += 1;
        }

        if mat[j][j] == 0 {
            return -1;
        }

        inv = gf_inv(mat[j][j]);

        c = j;
        while c < SYS_T + 1 {
            mat[c][j] = gf_mul(mat[c][j], inv);

            c += 1;
        }

        for k in 0..SYS_T {
            if k != j {
                t = mat[j][k];

                c = j;
                while c < SYS_T + 1 {
                    mat[c][k] ^= gf_mul(mat[c][j], t);
                    c += 1;
                }
            }
        }
    }

    for i in 0..SYS_T {
        out[i] = mat[SYS_T][i];
    }

    return 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "mceliece8192128f", test))]
    pub fn test_genpoly_gen() {
        assert_eq!(SYS_T, 128);

        let mut first_round_input: [u16; SYS_T] = [
            7320, 7713, 1410, 6432, 1430, 2403, 2483, 4901, 1451, 5795, 1022, 5826, 4733, 3189,
            3015, 6733, 5468, 1121, 7525, 7388, 5224, 6261, 5738, 1484, 5943, 518, 3241, 3236,
            3906, 841, 2358, 7234, 927, 834, 620, 2358, 5951, 2305, 4983, 1323, 4885, 1615, 64,
            2221, 6521, 2511, 2958, 5361, 5216, 916, 7830, 4321, 7578, 6833, 4733, 6722, 1114,
            5045, 2921, 3301, 5086, 4259, 5954, 7170, 4141, 3999, 1628, 6970, 8149, 3807, 1398,
            7668, 2820, 3247, 2823, 6525, 4383, 7676, 7093, 7574, 2039, 1512, 382, 4827, 6680,
            5475, 6164, 7433, 2288, 3324, 244, 7815, 2312, 4399, 49, 462, 3608, 960, 753, 5906,
            4294, 562, 8056, 4839, 3099, 1084, 788, 4252, 6204, 2354, 6361, 5254, 7986, 8069, 5930,
            1410, 2800, 277, 4866, 953, 6049, 2438, 756, 5764, 6388, 7959, 4195, 5039,
        ];

        let mut first_round_output: [u16; SYS_T] = [
            3527, 4824, 7803, 7587, 2174, 7398, 2244, 4114, 3189, 2305, 7465, 563, 3272, 1133,
            6722, 1257, 6177, 3691, 3030, 2892, 1969, 4664, 6012, 2238, 832, 3782, 3965, 3277,
            2780, 4209, 6021, 6869, 6216, 6660, 7513, 7481, 1919, 1698, 1269, 4319, 1875, 3083,
            3618, 1547, 5962, 3653, 5143, 6284, 5493, 2576, 7539, 2669, 1945, 5767, 6269, 521,
            6521, 4186, 629, 31, 355, 5757, 4798, 5310, 2624, 3357, 6743, 74, 7547, 1192, 3451,
            5525, 1849, 1523, 3951, 3392, 5614, 7992, 3241, 1366, 1598, 6634, 6571, 7512, 4004, 51,
            1475, 1503, 3031, 5720, 7715, 6376, 1614, 6248, 4597, 6598, 1232, 5710, 1159, 4223,
            4877, 6430, 1775, 4519, 2486, 6610, 808, 3068, 4002, 4160, 376, 8102, 7640, 1400, 7328,
            2117, 949, 1362, 5919, 5106, 4442, 2587, 6290, 1798, 256, 6708, 6111, 6697,
        ];

        let mut output = [0u16; SYS_T];

        genpoly_gen(&mut output, &mut first_round_input);

        assert_eq!(output, first_round_output);
    }
}
