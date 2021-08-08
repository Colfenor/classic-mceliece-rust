use crate::transpose;

//

pub fn print_matrix(m: [u64; 64]) {
    
    for i in 0..64 {
        for j in 0..64 {
            print!("{}", (m[i] >> (63 - j)) & 1);
        }
        print!("\n");
    }
}

fn setup_exected_result() -> [u64; 64] {

    let mut expected_result: [u64; 64] = [0; 64];

    expected_result[0] = 3074457345618258602;
    expected_result[1] = 5534023222112865484;
    expected_result[2] = 8138269444283625712;
    expected_result[3] = 9151594822560186112;
    expected_result[4] = 9223090566172966912;
    expected_result[5] = 9223372032559808512;

    expected_result
}

#[test]
pub fn test_transpose() {

    let mut test_input: [u64; 64] = [0; 64];
    let mut test_output: [u64; 64] = [0; 64];

    let expected_result = setup_exected_result();

    for i in 0..63 {
        test_input[i] = i as u64;
    }

    println!("Initial matrix:");
    print_matrix(test_input);

    transpose::transpose(&mut test_output, test_input);

    println!("transposed matrix:");
    print_matrix(test_output);

    // assert matrice elements are equal
    for g in 0..63 {
        assert_eq!(expected_result[g], test_output[g]);
    }

}