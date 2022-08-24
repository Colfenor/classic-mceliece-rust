use std::io::Write;
use std::io::{BufRead, BufReader};
use std::{env, error, fmt, fs};

use classic_mceliece_rust::{decapsulate, encapsulate, keypair};
use classic_mceliece_rust::{
    CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_PRIMITIVE, CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES,
};
use rand::RngCore;

use nist_aes_rng::AesState;

#[path = "../src/nist_aes_rng.rs"]
mod nist_aes_rng;

const KATNUM: usize = 100;

#[derive(Debug)]
struct InvalidFileFormat(String, usize);

impl error::Error for InvalidFileFormat {}

impl fmt::Display for InvalidFileFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "file has invalid format at line {}: {}", self.1, self.0)
    }
}

type R = Result<(), Box<dyn error::Error>>;

#[derive(Debug, PartialEq)]
struct Testcase {
    count: usize,
    seed: [u8; 48],
    pk: [u8; CRYPTO_PUBLICKEYBYTES],
    sk: [u8; CRYPTO_SECRETKEYBYTES],
    ct: [u8; CRYPTO_CIPHERTEXTBYTES],
    ss: [u8; CRYPTO_BYTES],
}

fn is_zero(x: &[u8]) -> bool {
    for b in x.iter() {
        if *b != 0 {
            return false;
        }
    }

    true
}

impl Testcase {
    fn new() -> Testcase {
        Testcase {
            count: 0,
            seed: [0u8; 48],
            pk: [0u8; CRYPTO_PUBLICKEYBYTES],
            sk: [0u8; CRYPTO_SECRETKEYBYTES],
            ct: [0u8; CRYPTO_CIPHERTEXTBYTES],
            ss: [0u8; CRYPTO_BYTES],
        }
    }

    fn with_seed(count: usize, seed: &[u8; 48]) -> Testcase {
        Testcase {
            count,
            seed: *seed,
            pk: [0u8; CRYPTO_PUBLICKEYBYTES],
            sk: [0u8; CRYPTO_SECRETKEYBYTES],
            ct: [0u8; CRYPTO_CIPHERTEXTBYTES],
            ss: [0u8; CRYPTO_BYTES],
        }
    }

    fn write_to_file(&self, fd: &mut fs::File) -> R {
        let repr_bytes = |bytes: &[u8]| -> String {
            if is_zero(&bytes) {
                "".to_string()
            } else {
                format!(" {}", hex::encode_upper(bytes))
            }
        };

        writeln!(fd, "count = {}", self.count)?;
        writeln!(fd, "seed = {}", hex::encode_upper(self.seed))?;
        writeln!(fd, "pk ={}", repr_bytes(&self.pk).as_str())?;
        writeln!(fd, "sk ={}", repr_bytes(&self.sk).as_str())?;
        writeln!(fd, "ct ={}", repr_bytes(&self.ct).as_str())?;
        writeln!(fd, "ss ={}\n", repr_bytes(&self.ss).as_str())?;

        Ok(())
    }

    /// Parse one line of a `.rsp` file. Returns true if data in the
    /// expected format has been successfully stored in `self`.
    /// Returns false, if the line is empty (acts as record separator).
    fn read_line(&mut self, line: &str, lineno: usize) -> Result<bool, Box<dyn error::Error>> {
        let err = |msg: &str| -> Result<bool, Box<dyn error::Error>> {
            Err(Box::new(InvalidFileFormat(msg.to_string(), lineno)))
        };

        if line.starts_with('#') {
            return Ok(true);
        }
        if line.trim() == "" {
            return Ok(false);
        }

        let mut fields = line.split("=");
        let name = match fields.nth(0) {
            Some(n) => n.trim(),
            None => return err("could not split key with '=' assignment operator"),
        };
        let value = match fields.nth(0) {
            Some(v) => v.trim(),
            None => return err("could not split value with '=' assignment operator"),
        };

        match name {
            "count" => self.count = value.parse::<usize>()?,
            "seed" => hex::decode_to_slice(value, &mut self.seed as &mut [u8])?,
            "pk" => hex::decode_to_slice(value, &mut self.pk as &mut [u8])?,
            "sk" => hex::decode_to_slice(value, &mut self.sk as &mut [u8])?,
            "ct" => hex::decode_to_slice(value, &mut self.ct as &mut [u8])?,
            "ss" => hex::decode_to_slice(value, &mut self.ss as &mut [u8])?,
            _ => return err(&format!("assignment to unknown key '{}'", name)),
        };

        Ok(true)
    }

    fn read_from_file(&mut self, reader: &mut BufReader<fs::File>) -> R {
        for (lineno, line) in reader.lines().enumerate() {
            if !self.read_line(&line?, lineno)? {
                return Ok(());
            }
        }

        Ok(())
    }
}

impl Eq for Testcase {}

impl fmt::Display for Testcase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NOTE it requires a new struct with multiple implementations
        //   to abstract Testcase.write_to_file(…) for stdout AND files.
        //   As a result, I decided to duplicate the code.
        let repr_bytes = |bytes: &[u8]| -> String {
            if is_zero(&bytes) {
                "".to_string()
            } else {
                format!(" {}", hex::encode_upper(bytes))
            }
        };

        writeln!(f, "count = {}", self.count)?;
        writeln!(f, "seed = {}", hex::encode_upper(self.seed))?;
        writeln!(f, "pk ={}", repr_bytes(&self.pk).as_str())?;
        writeln!(f, "sk ={}", repr_bytes(&self.sk).as_str())?;
        writeln!(f, "ct ={}", repr_bytes(&self.ct).as_str())?;
        writeln!(f, "ss ={}\n", repr_bytes(&self.ss).as_str())
    }
}

fn create_request_file(filepath: &str) -> R {
    let mut fd = fs::File::create(filepath)?;

    // initialize RNG
    let mut entropy_input = [0u8; 48];
    for i in 0..48 {
        entropy_input[i] = i as u8;
    }
    let mut rng = AesState::new();
    rng.randombytes_init(entropy_input);

    // create KATNUM testcase seeds
    for t in 0..KATNUM {
        let mut tc = Testcase::new();
        tc.count = t;
        rng.fill_bytes(&mut tc.seed);

        tc.write_to_file(&mut fd)?;
    }

    Ok(())
}

fn create_response_file(filepath: &str) -> R {
    let mut fd = fs::File::create(filepath)?;
    writeln!(&mut fd, "# kem/{}\n", CRYPTO_PRIMITIVE)?;

    // initialize RNG
    let mut entropy_input = [0u8; 48];
    for i in 0..48 {
        entropy_input[i] = i as u8;
    }
    let mut rng = AesState::new();
    rng.randombytes_init(entropy_input);

    // create KATNUM testcase seeds
    for t in 0..KATNUM {
        let mut tc = Testcase::new();
        tc.count = t;
        rng.fill_bytes(&mut tc.seed);

        let mut tc_rng = AesState::new();
        tc_rng.randombytes_init(tc.seed);

        let mut pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk_buf = [0u8; CRYPTO_SECRETKEYBYTES];
        let mut ss_buf1 = [0u8; CRYPTO_BYTES];
        let mut ss_buf2 = [0u8; CRYPTO_BYTES];

        let (pk, sk) = keypair(&mut pk_buf, &mut sk_buf, &mut tc_rng);
        let (ct, ss) = encapsulate(&pk, &mut ss_buf1, &mut tc_rng);
        let ss2 = decapsulate(&ct, &sk, &mut ss_buf2);

        tc.pk = *pk.as_array();
        tc.sk = *sk.as_array();
        assert_eq!(ss.as_array(), ss2.as_array());
        tc.ss = *ss.as_array();
        tc.ct.copy_from_slice(ct.as_ref());
        tc.write_to_file(&mut fd)?;
    }

    Ok(())
}

fn verify(filepath: &str) -> R {
    let fd = fs::File::open(filepath)?;
    let mut reader = BufReader::new(fd);
    let mut rng = AesState::new();

    // first record in a response file is empty (e.g. “# ntruhps2048509\n”)
    // hence, skip it
    let mut expected = Testcase::new();
    expected.read_from_file(&mut reader)?;

    // create KATNUM testcase seeds
    for t in 0..KATNUM {
        let mut expected = Testcase::new();
        expected.read_from_file(&mut reader)?;

        rng.randombytes_init(expected.seed);

        let mut actual = Testcase::with_seed(t, &expected.seed);

        let mut pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk_buf = [0u8; CRYPTO_SECRETKEYBYTES];
        let mut ss_buf1 = [0u8; CRYPTO_BYTES];
        let mut ss_buf2 = [0u8; CRYPTO_BYTES];

        let (pk, sk) = keypair(&mut pk_buf, &mut sk_buf, &mut rng);
        let (ct, ss) = encapsulate(&pk, &mut ss_buf1, &mut rng);
        let ss2 = decapsulate(&ct, &sk, &mut ss_buf2);

        actual.pk = *pk.as_array();
        actual.sk = *sk.as_array();
        assert_eq!(ss.as_array(), ss2.as_array());
        actual.ss = *ss.as_array();
        actual.ct.copy_from_slice(ct.as_ref());

        //assert_eq!(expected, actual);
        assert_eq!(
            expected.seed, actual.seed,
            "seeds of testcase {} don't match",
            expected.count
        );
        assert_eq!(
            expected.pk, actual.pk,
            "public keys of testcase {} don't match",
            expected.count
        );
        assert_eq!(
            expected.sk, actual.sk,
            "secret keys of testcase {} don't match",
            expected.count
        );
        assert_eq!(
            expected.ct, actual.ct,
            "ciphertexts of testcase {} don't match",
            expected.count
        );
        assert_eq!(
            expected.ss, actual.ss,
            "shared secrets of testcase {} don't match",
            expected.count
        );
    }

    Ok(())
}

fn main() -> R {
    let mut args = env::args();
    match args.len() {
        2 => {
            args.next().unwrap();
            let rsp_file = args.next().unwrap();
            verify(&rsp_file)?;

            println!("Verification successful.");
        }

        3 => {
            args.next().unwrap();
            let req_file = args.next().unwrap();
            let rsp_file = args.next().unwrap();

            create_request_file(&req_file)?;
            create_response_file(&rsp_file)?;

            println!("request and response file created.");
        }

        _ => {
            eprintln!("usage: ./PQCgenKAT_kem <request:filepath> <response:filepath>");
            eprintln!("  generate a request and response file\n");
            eprintln!("usage: ./PQCgenKAT_kem <response:filepath>");
            eprintln!("  verify the given response file\n");
            panic!("wrong number of arguments");
        }
    }

    Ok(())
}
