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
