mod api;
mod benes;
mod bm;
mod controlbits;
mod controlbits_arrays;
mod crypto_hash;
mod decrypt;
mod decrypt_arrays;
mod encrypt;
mod encrypt_array;
mod gf;
mod int32_sort;
mod operations;
mod operations_arrays;
mod params;
mod pk_gen;
mod pk_gen_arrays;
mod randombytes;
mod root;
mod sk_gen;
mod synd;
mod transpose;
mod uint64_sort;
mod util;

fn main() {
    let a = 65u64;
    println!("{}", a);

    //test_transpose::test_transpose();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::error::Error;
    use std::fmt;

    #[derive(Debug)]
    struct CryptoError<'a>(&'a str, i32);

    impl<'a> fmt::Display for CryptoError<'a> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{} returned <{}>", self.0, self.1)
        }
    }

    impl<'a> Error for CryptoError<'a> {}

    #[test]
    fn test_kat_tests() -> Result<(), Box<dyn Error>> {
        const KATNUM: usize = 10;

        let mut entropy_input = [0u8; 48];
        let mut seed = [[0u8; 48]; KATNUM];

        for i in 0..48 {
            entropy_input[i] = i as u8;
        }
        randombytes::randombytes_init(&mut entropy_input, &[0u8; 48], 256)?;

        for i in 0..KATNUM {
            randombytes::randombytes(&mut seed[i], 48)?;
        }

        let fp_req = &mut File::create("kat_kem.req")?;

        for i in 0..KATNUM {
            kat_test_request(fp_req, i, &seed[i])?;
        }

        let fp_rsp = &mut File::create("kat_kem.rsp")?;
        writeln!(fp_rsp, "# kem/{}\n", api::CRYPTO_PRIMITIVE)?;

        for i in 0..KATNUM {
            kat_test_response(fp_rsp, i, &seed[i])?;
        }

        Ok(())
    }

    fn kat_test_request(fp_req: &mut File, i: usize, seed: &[u8; 48]) -> Result<(), Box<dyn Error>> {
        writeln!(fp_req, "count = {}", i)?;
        writeln!(fp_req, "seed = {}", repr_binary_str(seed))?;
        writeln!(fp_req, "pk =")?;
        writeln!(fp_req, "sk =")?;
        writeln!(fp_req, "ct =")?;
        writeln!(fp_req, "ss =\n")?;
        Ok(())
    }

    fn kat_test_response(fp_rsp: &mut File, i: usize, seed: &[u8; 48]) -> Result<(), Box<dyn Error>> {
        let mut ct = [0u8; api::CRYPTO_CIPHERTEXTBYTES];
        let mut ss = [0u8; api::CRYPTO_BYTES];
        let mut ss1 = [0u8; api::CRYPTO_BYTES];
        let mut pk = vec![0u8; api::CRYPTO_PUBLICKEYBYTES];
        let mut sk = vec![0u8; api::CRYPTO_SECRETKEYBYTES];

        randombytes::randombytes_init(seed, &[0u8; 48], 256)?;

        writeln!(fp_rsp, "count = {}", i)?;
        writeln!(fp_rsp, "seed = {}", repr_binary_str(seed))?;

        let ret_kp = operations::crypto_kem_keypair(&mut pk, &mut sk);
        if ret_kp != 0 {
            return Err(Box::new(CryptoError("crypto_kem_keypair", ret_kp)));
        }

        writeln!(fp_rsp, "pk = {}", repr_binary_str(&pk))?;
        writeln!(fp_rsp, "sk = {}", repr_binary_str(&sk))?;

        let ret_enc = operations::crypto_kem_enc(&mut ct, &mut ss, &mut pk);
        if ret_enc != 0 {
            return Err(Box::new(CryptoError("crypto_kem_enc", ret_enc)));
        }

        writeln!(fp_rsp, "ct = {}", repr_binary_str(&ct))?;
        writeln!(fp_rsp, "ss = {}", repr_binary_str(&ss))?;
        writeln!(fp_rsp, "")?;

        let ret_dec = operations::crypto_kem_dec(&mut ss1, &mut ct, &mut sk);
        if ret_dec != 0 {
            return Err(Box::new(CryptoError("crypto_kem_dec", ret_dec)));
        }

        if ss != ss1 {
            return Err(Box::new(CryptoError("crypto_kem_dec ss cmp", 1)));
        }

        Ok(())
    }

    fn repr_binary_str(a: &[u8]) -> String {
        let mut s = String::new();

        for v in a.iter() {
            s.push_str(&format!("{:02X}", v));
        }

        if a.is_empty() {
            s.push_str("00");
        }

        s
    }
}
