use crate::transpose;

pub fn print_matrix(m: [u64; 64]) {
    
    for i in 0..64 {
        for j in 0..64 {
            print!("{}", (m[i] >> (63 - j)) & 1);
        }
        print!("\n");
    }
}

pub fn test_transpose() {

    let mut test_input: [u64; 64] = [0; 64];
    let mut test_output: [u64; 64] = [0; 64];

    for i in 0..63 {
        test_input[i] = i as u64;
    }

    println!("Initial matrix:");
    print_matrix(test_input);

    transpose::transpose(&mut test_output, test_input);

    println!("transposed matrix:");
    print_matrix(test_output);

}