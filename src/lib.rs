mod api;
mod benes;
mod bm;
mod controlbits;
mod crypto_hash;
mod decrypt;
mod encrypt;
mod gf;
mod int32_sort;
mod operations;
mod params;
mod pk_gen;
mod randombytes;
mod root;
mod sk_gen;
mod synd;
mod transpose;
mod uint64_sort;
mod util;

pub use randombytes::{AesState, RNGState};
pub use operations::{crypto_kem_dec, crypto_kem_enc, crypto_kem_keypair};
pub use api::{
    CRYPTO_BYTES, CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES, CRYPTO_CIPHERTEXTBYTES,
    CRYPTO_PRIMITIVE
};

#[cfg(test)]
macro_rules! impl_parser_per_type {
    ($name:ident, $bitsize:expr, $t:ty) => {
        /// Parses a testdata file and returns a vector of $ty stored for the given `search_key`.
        /// The value is parsed in big-endian order.
        ///
        /// I started to write a zero-allocation parser, but it takes many lines of code.
        /// This design allocates, but can be comprehended much easier.
        fn $name(&self, search_key: &str) -> Vec<$t> {
            use std::str;
            use std::convert::TryInto;

            let content = match str::from_utf8(self.data) {
                Ok(v) => v,
                Err(e) => panic!("testdata.txt contains invalid UTF-8 data: {}", e),
            };

            for (lineno, line) in content.lines().enumerate() {
                let inner_line = line.trim();
                if inner_line.starts_with('#') {
                    continue;
                }
                let mut key = "";
                let mut value = "";
                for (f, field) in inner_line.split('=').enumerate() {
                    match f {
                        0 => key = field.trim(),
                        1 => value = field.trim(),
                        _ => {},
                    }
                }
                if key != search_key {
                    continue;
                }
                if value == "" {
                    panic!("empty value for key '{}' at line {}", search_key, lineno);
                }
                let bytes = hex::decode(value).expect("invalid hex data in value");
                let bytes_per_element = $bitsize / 8;
                let elements_count = bytes.len() / bytes_per_element;
                let mut elements = Vec::<$t>::with_capacity(elements_count);
                for idx in 0..elements_count {
                    let element = &bytes[bytes_per_element*idx .. bytes_per_element*(idx + 1)];
                    elements.push(<$t>::from_be_bytes(element.try_into().expect("invalid slice length")));
                }
                return elements;
            }

            panic!("search_key '{}' not found in testdata.txt", search_key);
        }
    }
}


#[cfg(test)]
struct TestData {
    data: &'static [u8],
}

#[cfg(test)]
impl TestData {
    fn new() -> TestData {
        let bytes = include_bytes!("../data/testdata.txt");
        TestData { data: bytes }
    }

    impl_parser_per_type!(u8vec, 8, u8);
    impl_parser_per_type!(u16vec, 16, u16);
    impl_parser_per_type!(u32vec, 32, u32);
    impl_parser_per_type!(u64vec, 64, u64);
    impl_parser_per_type!(i8vec, 8, i8);
    impl_parser_per_type!(i16vec, 16, i16);
    impl_parser_per_type!(i32vec, 32, i32);
    impl_parser_per_type!(i64vec, 64, i64);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::error::Error;
    use std::fmt;

    #[derive(Debug)]
    struct CryptoError<'a>(&'a str, String);

    impl<'a> fmt::Display for CryptoError<'a> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{} failed: {}", self.0, self.1)
        }
    }

    impl<'a> Error for CryptoError<'a> {}

    #[test]
    fn test_kat_tests() -> Result<(), Box<dyn Error>> {
        const KATNUM: usize = 10;
        let mut rng = AesState::new();

        let mut entropy_input = [0u8; 48];
        let mut seed = [[0u8; 48]; KATNUM];

        for i in 0..48 {
            entropy_input[i] = i as u8;
        }
        rng.randombytes_init(entropy_input);

        for i in 0..KATNUM {
            rng.randombytes(&mut seed[i])?;
        }

        let fp_req = &mut File::create("kat_kem.req")?;

        for i in 0..KATNUM {
            kat_test_request(fp_req, i, &seed[i])?;
        }

        let fp_rsp = &mut File::create("kat_kem.rsp")?;
        writeln!(fp_rsp, "# kem/{}\n", api::CRYPTO_PRIMITIVE)?;

        for i in 0..KATNUM {
            kat_test_response(fp_rsp, i, seed[i])?;
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

    fn kat_test_response(fp_rsp: &mut File, i: usize, seed: [u8; 48]) -> Result<(), Box<dyn Error>> {
        let mut ct = [0u8; api::CRYPTO_CIPHERTEXTBYTES];
        let mut ss = [0u8; api::CRYPTO_BYTES];
        let mut ss1 = [0u8; api::CRYPTO_BYTES];
        let mut pk = vec![0u8; api::CRYPTO_PUBLICKEYBYTES];
        let mut sk = vec![0u8; api::CRYPTO_SECRETKEYBYTES];
        let mut rng = AesState::new();

        rng.randombytes_init(seed);

        writeln!(fp_rsp, "count = {}", i)?;
        writeln!(fp_rsp, "seed = {}", repr_binary_str(&seed))?;

        if let Err(ret_kp) = operations::crypto_kem_keypair(&mut pk, &mut sk, &mut rng) {
            return Err(Box::new(CryptoError("crypto_kem_keypair", ret_kp.to_string())));
        }

        writeln!(fp_rsp, "pk = {}", repr_binary_str(&pk))?;
        writeln!(fp_rsp, "sk = {}", repr_binary_str(&sk))?;

        if let Err(ret_enc) = operations::crypto_kem_enc(&mut ct, &mut ss, &mut pk, &mut rng) {
            return Err(Box::new(CryptoError("crypto_kem_enc", ret_enc.to_string())));
        }

        writeln!(fp_rsp, "ct = {}", repr_binary_str(&ct))?;
        writeln!(fp_rsp, "ss = {}", repr_binary_str(&ss))?;
        writeln!(fp_rsp, "")?;

        if let Err(ret_dec) = operations::crypto_kem_dec(&mut ss1, &mut ct, &mut sk) {
            return Err(Box::new(CryptoError("crypto_kem_dec", ret_dec.to_string())));
        }

        if ss != ss1 {
            return Err(Box::new(CryptoError("crypto_kem_dec", "shared keys of both parties do not match".to_string())));
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

    #[test]
    fn testdata_sanity_check() {
        assert_eq!(TestData::new().u8vec("sanity_check"), [0x01, 0x23, 0x45, 0x67].to_vec());
        assert_eq!(TestData::new().u16vec("sanity_check"), [0x0123, 0x4567].to_vec());
        assert_eq!(TestData::new().u32vec("sanity_check"), [0x01234567].to_vec());
    }
}
