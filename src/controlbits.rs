pub fn permutation(c: &[u8]) -> Vec<u8> {
    let mut m = 1;
    while ((2 * m - 1) << (m - 1)) < c.len() {
        m += 1
    }
    eprintln!("{} -> {}", m, c.len());
    assert_eq!((2 * m - 1) << (m - 1), c.len());

    let n = 1 << m;
    let mut pi = vec![0u8; n];
    for i in 0..n {
        pi[i] = i as u8;
    }

    for i in 0..(2 * m - 1) {
        let gap = 1 << (if i < 2 * m - 2 - i { i } else { 2 * m - 2 - i });
        for j in 0..(n / 2) {
            if c[i * n / 2 + j] > 0 {
                let pos = (j % gap) + 2 * gap * (j / gap);
                let tmp = pi[pos];
                pi[pos] = pi[pos + gap];
                pi[pos + gap] = tmp;
            }
        }
    }

    pi
}

pub fn composeinv(c: &[u8], pi: &[u8]) -> Vec<u8> {
    let mut it = pi.iter().zip(c.iter()).collect::<Vec<(&u8, &u8)>>();
    it.sort();
    it.iter().map(|v| *(v.1)).collect::<Vec<u8>>()
}

pub fn controlbits(pi: &[u8]) -> Vec<u8> {
    let n = pi.len();
    let mut m = 1;
    while (1 << m) < n {
        m += 1;
    }
    assert_eq!(1 << m, n);

    if m == 1 {
        return vec![pi[0]];
    }
    let mut pre_p = vec![0u8; n];
    let mut pre_q = vec![0u8; n];
    let mut range = vec![0u8; n];
    for x in 0..n {
        pre_p[x] = pi[x ^ 1];
        pre_q[x] = pi[x] ^ 1;
        range[x] = x as u8;
    }

    let piinv = composeinv(&range, pi);
    let mut p = composeinv(&pre_p, &pre_q);
    let mut q = composeinv(&pre_q, &pre_p);

    let mut c = vec![0u8; n];
    for x in 0..n {
        c[x] = if (x as u8) < p[x] { x as u8 } else { p[x] };
    }
    for _ in 1..(m - 1) {
        let cp = composeinv(&c, &q);
        let p_updated = composeinv(&p, &q);
        q = composeinv(&q, &p);
        p = p_updated;

        c = range
            .iter()
            .map(|x| u8::min(c[*x as usize], cp[*x as usize]))
            .collect::<Vec<u8>>();
    }

    let f: Vec<u8> = (0..(n / 2)).map(|j| c[2 * j] % 2).collect();
    let ff: Vec<u8> = (0..n).map(|x| (x as u8) ^ f[x / 2]).collect();
    let ff_pi = composeinv(&ff, &piinv);
    let l: Vec<u8> = (0..(n / 2)).map(|k| ff_pi[2 * k] % 2).collect();
    let ll: Vec<u8> = (0..n).map(|y| (y as u8) ^ l[y / 2]).collect();
    let mm: Vec<u8> = composeinv(&ff_pi, &ll);

    let sub_m0: Vec<u8> = (0..(n / 2)).map(|j| mm[2 * j + 0] / 2).collect();
    let sub_m1: Vec<u8> = (0..(n / 2)).map(|j| mm[2 * j + 1] / 2).collect();
    let subz0 = controlbits(&sub_m0);
    let subz1 = controlbits(&sub_m1);
    let mut z = Vec::with_capacity(n);
    z.extend_from_slice(&f);
    for s0s1 in subz0.iter().zip(subz1.iter()) {
        z.push(*s0s1.0);
        z.push(*s0s1.1);
    }
    z.extend_from_slice(&l);

    z
}

// an adapter for controlbitsfrompermutation
pub fn controlbitsfrompermutation(out: &mut [u8], pi: &[i16], w: usize, n: usize) {
    assert_eq!(pi.len(), n);
    assert_eq!(pi.len(), 1 << w);

    let mut pi_as_u8 = vec![];
    for i in 0..pi.len() {
        pi_as_u8.push((pi[i] & 0xFF) as u8);
        pi_as_u8.push((pi[i] >> 8) as u8);
    }
    let result = controlbits(&pi_as_u8);
    assert_eq!(result.len(), out.len());
    out.copy_from_slice(&result);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permutation_1() {
        let perm = permutation(&[0u8, 4, 3, 2, 1, 5]);
        assert_eq!(perm.as_slice(), [2, 3, 1, 0]);
    }

    #[test]
    fn test_permutation_2() {
        let perm = permutation(&[3u8, 4, 0, 1, 2, 5]);
        assert_eq!(perm.as_slice(), [2, 1, 0, 3]);
    }

    #[test]
    fn test_composeinv_1() {
        let inv = composeinv(&[11u8, 22, 33, 44], &[0, 3, 2, 1]);
        assert_eq!(inv, [11, 44, 33, 22]);
    }

    #[test]
    fn test_composeinv_2() {
        let inv = composeinv(&[1, 2, 3, 4, 5, 6, 7, 8], &[4, 2, 1, 3, 0, 7, 5, 6]);
        assert_eq!(inv, [5, 3, 2, 4, 1, 7, 8, 6]);
    }

    #[test]
    fn test_composeinv_3() {
        let mut r = [0u8; 16];
        for i in 0..16 {
            r[i] = i as u8;
        }
        let inv = composeinv(&r, &r);
        assert_eq!(inv, &r);
    }

    #[test]
    fn test_controlbits_1() {
        let cb = controlbits(&[3u8, 2, 1, 0]);
        assert_eq!(cb, [0, 0, 1, 1, 1, 1]);
    }

    #[test]
    fn test_controlbits_2() {
        let cb = controlbits(&[1, 3, 2, 4, 6, 5, 0, 7]);
        assert_eq!(
            cb,
            [0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0]
        );
    }
}
