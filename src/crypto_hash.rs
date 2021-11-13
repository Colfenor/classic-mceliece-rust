use std::io::{Read, Write};

use sha3::{
    digest::{ExtendableOutput, Update},
    Digest, Shake256,
};

use crate::gf::SYND_BYTES;

/*


in the mceliece8192128f implementation
crypto_hash_32b(..)
uses: out

todo test the c implementation shake on
test input and see what the output is

*/
#[test]
pub fn crypto_hash_32b() {
    println!("synd:{}", SYND_BYTES); // 208 + 240 c

    let mut c = [0u8; 32]; // size determines how many bytes are read
    let mut two_e = [0u8; 1026];
    two_e[0] = 2; //inlen -> sizeof(two_e) == 1025;

    let mut shake_hash_fn = Shake256::default();

    shake_hash_fn.update(two_e);

    //let result_shake = _shake_hash_fn.finalize_xof();
    let mut result_shake = shake_hash_fn.finalize_xof();

    result_shake.read(&mut c);

    for i in 0..c.len() {
        println!("i:{} c:{}", i, c[i]);
    }

    println!("done");
}
