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

pub use randombytes::{AesState, RNGState};
pub use operations::{crypto_kem_dec, crypto_kem_enc, crypto_kem_keypair};
pub use api::{
    CRYPTO_BYTES, CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES, CRYPTO_CIPHERTEXTBYTES,
    CRYPTO_PRIMITIVE
};

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

    /// Parses a line of the testdata file.
    ///
    /// Given the index of the first character of the line (start-of-line)
    /// and the last character of the line (end-of-line, linebreak or EOF),
    /// return (a, b, c, d) such that `self.data[a..b]` gives the key and
    /// `self.data[c..d]` gives the value.
    /*fn parse_line(&self, sol: usize, eol: usize) -> (usize, usize, usize, usize) {
        assert!(sol <= eol);

        let mut key_start = sol;
        let mut key_end = sol;
        let mut value_start = sol;
        let mut value_end = sol;
        let mut state = 0;

        for idx in sol..eol {
            match state {
                // skip whitespace before key
                0 => {
                    if !self.data[key_start].is_ascii_whitespace() {
                        key_end = key_start;
                        state = 1;
                    } else {
                        key_start += 1;
                    }
                },
                // read key
                1 => {
                    if self.data[key_end].is_ascii_whitespace() || self.data[key_end] == b'=' {
                        value_start = key_end;
                        state = 2;
                    } else {
                        key_end += 1;
                    }
                },
                // skip delimiter
                2 => {
                    if self.data[key_end].is_ascii_whitespace() || self.data[key_end] == b'=' {
                        value_start = key_end;
                        state = 3;
                    } else {
                        key_end += 1;
                    }
                }
                …
            }
        }

        (key_start, key_end, value_start, value_end)
    }*/

    /// Parses a testdata file and returns a vector of u16 stored for the given `search_key`.
    /// The value is parsed in big-endian order.
    ///
    /// I started to write a zero-allocation parser, but it takes many lines of code.
    /// This design allocates, but can be comprehended much easier.
    fn u16vec(&self, search_key: &str) -> Vec<u16> {
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
            let u8_array = hex::decode(value).expect("invalid hex data in value");
            let mut u16_array = Vec::<u16>::with_capacity(u8_array.len());
            for idx in 0..(u8_array.len() / 2) {
                u16_array[idx] = u16::from_be_bytes(u8_array[2*idx .. 2*idx + 2].try_into().expect("invalid slice length"));
            }
            return u16_array;
        }

        panic!("search_key '{}' not found in testdata.txt", search_key);
    }

    /// Parses a testdata file and returns a vector of u8 stored for the given `search_key`.
    ///
    /// I started to write a zero-allocation parser, but it takes many lines of code.
    /// This design allocates, but can be comprehended much easier.
    fn u8vec(&self, search_key: &str) -> Vec<u8> {
        use std::str;

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
            return hex::decode(value).expect("invalid hex data in value");
        }

        panic!("search_key '{}' not found in testdata.txt", search_key);
    }
}

#[cfg(test)]
mod tests {
    use aes::Aes128;

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
    fn test_value() {
        assert_eq!(TestData::new().u8vec("hello"), [0x01, 0x23, 0x45, 0x67].to_vec());
    }
}
