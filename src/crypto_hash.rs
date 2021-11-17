use std::io::{Read, Write};

use sha3::{
    digest::{ExtendableOutput, Update},
    Digest, Shake256,
};

use crate::gf::SYND_BYTES;

/*
wrapper for the Shake256 hashing algo
*/
pub fn shake256(output: &mut [u8; 448], input: [u8; 1025]) {
    let mut shake_hash_fn = Shake256::default();
    shake_hash_fn.update(input);

    let mut result_shake = shake_hash_fn.finalize_xof();
    result_shake.read(output);
}

// todo find out how to read input at specific position
#[test]
pub fn test_shake256() {
    println!("synd:{}", SYND_BYTES); // 208 + 240 c

    let mut c = [0u8; 448]; // size determines how many bytes are read
    let mut two_e = [0u8; 1025];
    two_e[0] = 2; //inlen -> sizeof(two_e) == 1025;

    shake256(&mut c, two_e);

    for i in 0..c.len() {
        println!("i:{} c:{}", i, c[i]);
    }

    println!("done");
}
