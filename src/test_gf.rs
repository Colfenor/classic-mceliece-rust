use crate::gf;

#[test]
pub fn test_gf_iszero() {
    let mut result_var = gf::gf_iszero(0);
    assert_eq!(result_var, 8191);

    result_var = gf::gf_iszero(1);
    assert_eq!(result_var, 0);

    result_var = gf::gf_iszero(65535);
    assert_eq!(result_var, 0);
}

#[test]
pub fn test_gf_add() {
    let mut result_var = gf::gf_add(0, 1);
    assert_eq!(result_var, 1);

    result_var = gf::gf_add(1, 0);
    assert_eq!(result_var, 1);

    result_var = gf::gf_add(1, 1);
    assert_eq!(result_var, 0);

    result_var = gf::gf_add(0, 0);
    assert_eq!(result_var, 0);
}

#[test]
pub fn test_gf_mul() {
    let mut result_var = gf::gf_mul(0, 5);
    assert_eq!(result_var, 0);

    result_var = gf::gf_mul(2, 6);
    assert_eq!(result_var, 12);
}

#[test]
pub fn test_gf_sq2() {
    let mut result_var = gf::gf_sq2(2);
    assert_eq!(result_var, 16);

    result_var = gf::gf_sq2(3);
    assert_eq!(result_var, 17);

    result_var = gf::gf_sq2(0);
    assert_eq!(result_var, 0);
}

#[test]
pub fn test_gf_sqmul() {
    let mut result_var = gf::gf_sqmul(2, 2);
    assert_eq!(result_var, 8);

    result_var = gf::gf_sqmul(2, 3);
    assert_eq!(result_var, 12);

    result_var = gf::gf_sqmul(3, 2);
    assert_eq!(result_var, 10);

    result_var = gf::gf_sqmul(0, 2);
    assert_eq!(result_var, 0);

    result_var = gf::gf_sqmul(2, 0);
    assert_eq!(result_var, 0);
}

#[test]
pub fn test_gf_sq2mul() {
    let mut result_var = gf::gf_sq2mul(2, 2);
    assert_eq!(result_var, 32);

    result_var = gf::gf_sq2mul(2, 3);
    assert_eq!(result_var, 48);

    result_var = gf::gf_sq2mul(3, 2);
    assert_eq!(result_var, 34);

    result_var = gf::gf_sq2mul(4, 2);
    assert_eq!(result_var, 512);

    result_var = gf::gf_sq2mul(5, 2);
    assert_eq!(result_var, 514);

    result_var = gf::gf_sq2mul(5, 0);
    assert_eq!(result_var, 0);

    result_var = gf::gf_sq2mul(0, 5);
    assert_eq!(result_var, 0);
}

#[test]
pub fn test_gf_frac() {
    let mut result_var = gf::gf_frac(0, 2);
    assert_eq!(result_var, 0);

    result_var = gf::gf_frac(1, 5);
    assert_eq!(result_var, 5);

    result_var = gf::gf_frac(2, 1);
    assert_eq!(result_var, 4109);
}

#[test]
pub fn test_gf_inv() {
    let mut result_var = gf::gf_inv(0);
    assert_eq!(result_var, 0);

    result_var = gf::gf_inv(1);
    assert_eq!(result_var, 1);

    result_var = gf::gf_inv(2);
    assert_eq!(result_var, 4109);

    result_var = gf::gf_inv(5);
    assert_eq!(result_var, 5467);
}

#[test]
pub fn test_GF_mul() {
    //todo
}
