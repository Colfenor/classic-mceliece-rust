#![cfg(all(test, feature = "kem", feature = "alloc"))]

use alloc::string::String;
use alloc::string::ToString;
use alloc::boxed::Box;
use rand::RngCore;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::error;
use std::fmt;
use std::fs;

use crate::nist_aes_rng::AesState;
use crate::test_utils::TestData;
use crate::{CRYPTO_PUBLICKEYBYTES,CRYPTO_SECRETKEYBYTES,CRYPTO_CIPHERTEXTBYTES,CRYPTO_BYTES,CRYPTO_PRIMITIVE};
use crate::{keypair,keypair_boxed,encapsulate,decapsulate};

/// We are trying to read the data/testdata.txt file.
/// If there is some issue, we generate this error
#[cfg(feature = "kem")]
#[derive(Debug)]
struct InvalidFileFormat(String, usize);

#[cfg(feature = "kem")]
impl error::Error for InvalidFileFormat {}

#[cfg(feature = "kem")]
impl fmt::Display for InvalidFileFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "file has invalid format at line {}: {}", self.1, self.0)
    }
}

/// the number of KAT testcases/seeds to generate
#[cfg(feature = "kem")]
const KATNUM: usize = 100;

/// Convenience result type
#[cfg(all(feature = "alloc", feature = "kem"))]
type R = Result<(), Box<dyn error::Error>>;

#[cfg(feature = "kem")]
#[derive(Debug, PartialEq)]
pub(crate) struct Testcase {
    count: usize,
    seed: [u8; 48],
    seed_kem: [u8; 48],
    pk: [u8; CRYPTO_PUBLICKEYBYTES],
    sk: [u8; CRYPTO_SECRETKEYBYTES],
    ct: [u8; CRYPTO_CIPHERTEXTBYTES],
    ss: [u8; CRYPTO_BYTES],
    pk_kem: [u8; CRYPTO_PUBLICKEYBYTES],
    sk_kem: [u8; CRYPTO_SECRETKEYBYTES],
    ct_kem: [u8; CRYPTO_CIPHERTEXTBYTES],
    ss_kem: [u8; CRYPTO_BYTES],
}

#[cfg(feature = "kem")]
impl Testcase {
    fn new() -> Testcase {
        Testcase {
            count: 0,
            seed: [0u8; 48],
            seed_kem: [0u8; 48],
            pk: [0u8; CRYPTO_PUBLICKEYBYTES],
            sk: [0u8; CRYPTO_SECRETKEYBYTES],
            ct: [0u8; CRYPTO_CIPHERTEXTBYTES],
            ss: [0u8; CRYPTO_BYTES],
            pk_kem: [0u8; CRYPTO_PUBLICKEYBYTES],
            sk_kem: [0u8; CRYPTO_SECRETKEYBYTES],
            ct_kem: [0u8; CRYPTO_CIPHERTEXTBYTES],
            ss_kem: [0u8; CRYPTO_BYTES],
        }
    }

    fn with_seed(count: usize, seed: &[u8; 48], seed_kem: &[u8; 48]) -> Testcase {
        Testcase {
            count,
            seed: *seed,
            seed_kem: *seed_kem,
            pk: [0u8; CRYPTO_PUBLICKEYBYTES],
            sk: [0u8; CRYPTO_SECRETKEYBYTES],
            ct: [0u8; CRYPTO_CIPHERTEXTBYTES],
            ss: [0u8; CRYPTO_BYTES],
            pk_kem: [0u8; CRYPTO_PUBLICKEYBYTES],
            sk_kem: [0u8; CRYPTO_SECRETKEYBYTES],
            ct_kem: [0u8; CRYPTO_CIPHERTEXTBYTES],
            ss_kem: [0u8; CRYPTO_BYTES],
        }
    }

    fn write_to_file(&self, fd: &mut fs::File) -> R {
        let repr_bytes = |bytes: &[u8]| -> String {
            if bytes.iter().all(|b| *b == 0) {
                "".to_string()
            } else {
                format!(" {}", hex::encode_upper(bytes))
            }
        };

        writeln!(fd, "count = {}", self.count)?;
        writeln!(fd, "seed = {}", hex::encode_upper(self.seed))?;
        writeln!(fd, "seed_kem = {}", hex::encode_upper(self.seed_kem))?;
        writeln!(fd, "pk ={}", repr_bytes(&self.pk).as_str())?;
        writeln!(fd, "sk ={}", repr_bytes(&self.sk).as_str())?;
        writeln!(fd, "ct ={}", repr_bytes(&self.ct).as_str())?;
        writeln!(fd, "ss ={}", repr_bytes(&self.ss).as_str())?;
        writeln!(fd, "pk_kem ={}", repr_bytes(&self.pk_kem).as_str())?;
        writeln!(fd, "sk_kem ={}", repr_bytes(&self.sk_kem).as_str())?;
        writeln!(fd, "ct_kem ={}", repr_bytes(&self.ct_kem).as_str())?;
        writeln!(fd, "ss_kem ={}\n", repr_bytes(&self.ss_kem).as_str())?;

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

        let mut fields = line.split('=');
        let name = match fields.next() {
            Some(n) => n.trim(),
            None => return err("could not split key with '=' assignment operator"),
        };
        let value = match fields.next() {
            Some(v) => v.trim(),
            None => return err("could not split value with '=' assignment operator"),
        };

        match name {
            "count" => self.count = value.parse::<usize>()?,
            "seed" => hex::decode_to_slice(value, &mut self.seed as &mut [u8])?,
            "seed_kem" => hex::decode_to_slice(value, &mut self.seed_kem as &mut [u8])?,
            "pk" => hex::decode_to_slice(value, &mut self.pk as &mut [u8])?,
            "sk" => hex::decode_to_slice(value, &mut self.sk as &mut [u8])?,
            "ct" => hex::decode_to_slice(value, &mut self.ct as &mut [u8])?,
            "ss" => hex::decode_to_slice(value, &mut self.ss as &mut [u8])?,
            "pk_kem" => hex::decode_to_slice(value, &mut self.pk_kem as &mut [u8])?,
            "sk_kem" => hex::decode_to_slice(value, &mut self.sk_kem as &mut [u8])?,
            "ct_kem" => hex::decode_to_slice(value, &mut self.ct_kem as &mut [u8])?,
            "ss_kem" => hex::decode_to_slice(value, &mut self.ss_kem as &mut [u8])?,
            _ => return err(&format!("assignment to unknown key '{}'", name)),
        };

        Ok(true)
    }

    fn read_from_file(&mut self, reader: &mut BufReader<fs::File>) -> R {
        for (lineno, line_result) in reader.lines().enumerate() {
            let line = line_result?;
            if !self.read_line(&line, lineno)? {
                return Ok(());
            }
        }

        Ok(())
    }
}

#[cfg(feature = "kem")]
impl Eq for Testcase {}

#[cfg(feature = "kem")]
impl fmt::Display for Testcase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NOTE it requires a new struct with multiple implementations
        //   to abstract Testcase.write_to_file(…) for stdout AND files.
        //   As a result, I decided to duplicate the code.
        let repr_bytes = |bytes: &[u8]| -> String {
            if bytes.iter().all(|b| *b == 0) {
                "".to_string()
            } else {
                format!(" {}", hex::encode_upper(bytes))
            }
        };

        writeln!(f, "count = {}", self.count)?;
        writeln!(f, "seed = {}", hex::encode_upper(self.seed))?;
        writeln!(f, "seed_kem = {}", hex::encode_upper(self.seed_kem))?;
        writeln!(f, "pk ={}", repr_bytes(&self.pk).as_str())?;
        writeln!(f, "sk ={}", repr_bytes(&self.sk).as_str())?;
        writeln!(f, "ct ={}", repr_bytes(&self.ct).as_str())?;
        writeln!(f, "ss ={}", repr_bytes(&self.ss).as_str())?;
        writeln!(f, "pk_kem ={}", repr_bytes(&self.pk_kem).as_str())?;
        writeln!(f, "sk_kem ={}", repr_bytes(&self.sk_kem).as_str())?;
        writeln!(f, "ct_kem ={}", repr_bytes(&self.ct_kem).as_str())?;
        writeln!(f, "ss_kem ={}\n", repr_bytes(&self.ss_kem).as_str())
    }
}


pub(crate) fn create_request_file(filepath: &str) -> R {
    let mut fd = fs::File::create(filepath)?;

    // initialize RNG
    let mut entropy_input = [0u8; 48];
    for (i, e) in entropy_input.iter_mut().enumerate() {
        *e = i as u8;
    }
    let mut rng = AesState::new();
    rng.randombytes_init(entropy_input);

    let mut rng_kem = AesState::new();
    rng_kem.randombytes_init(entropy_input);

    // create KATNUM testcase seeds
    for t in 0..KATNUM {
        let mut tc;
        #[cfg(feature = "alloc")]
        {
            tc = Box::new(Testcase::new());
        }
        #[cfg(not(feature = "alloc"))]
        {
            tc = Testcase::new();
        }
        tc.count = t;
        rng.fill_bytes(&mut tc.seed);
        rng_kem.fill_bytes(&mut tc.seed_kem);

        tc.write_to_file(&mut fd)?;
    }

    Ok(())
}

pub(crate) fn create_response_file(filepath: &str) -> R {
    use kem::{Decapsulator,Encapsulator};
    use crate::ClassicMcEliece;

    let mut fd = fs::File::create(filepath)?;
    writeln!(&mut fd, "# kem/{}\n", CRYPTO_PRIMITIVE)?;

    // initialize RNG
    let mut entropy_input = [0u8; 48];
    for (i, e) in entropy_input.iter_mut().enumerate() {
        *e = i as u8;
    }
    let mut rng = AesState::new();
    let mut rng_kem = AesState::new();
    rng.randombytes_init(entropy_input);
    rng_kem.randombytes_init(entropy_input);

    // create KATNUM testcase seeds
    for t in 0..KATNUM {
        let mut tc;
        #[cfg(feature = "alloc")]
        {
            tc = Box::new(Testcase::new());
        }
        #[cfg(not(feature = "alloc"))]
        {
            tc = Testcase::new();
        }
        tc.count = t;
        rng.fill_bytes(&mut tc.seed);

        let mut tc_rng = AesState::new();
        tc_rng.randombytes_init(tc.seed);

        let mut pk_buf;
        #[cfg(feature = "alloc")]
        {
            pk_buf = Box::new([0u8; CRYPTO_PUBLICKEYBYTES]);
        }
        #[cfg(not(feature = "alloc"))]
        {
            pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
        }
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

        let (pk_kem, sk_kem) = keypair_boxed(&mut rng_kem);
        let (ct_kem, ss_kem) = ClassicMcEliece.try_encap(&mut rng_kem, &pk_kem).unwrap();
        let ss2_kem = sk_kem.try_decap(&ct_kem).unwrap();

        tc.pk_kem = *pk_kem.as_array();
        tc.sk_kem = *sk_kem.as_array();
        assert_eq!(ss_kem.as_bytes(), ss2_kem.as_bytes());
        tc.ss_kem.copy_from_slice(ss_kem.as_bytes());
        tc.ct_kem.copy_from_slice(ct_kem.as_ref());

        tc.write_to_file(&mut fd)?;
    }

    Ok(())
}

pub(crate) fn verify(filepath: &str) -> R {
    use kem::{Decapsulator, Encapsulator};
    use crate::ClassicMcEliece;

    let fd = fs::File::open(filepath)?;
    let mut reader = BufReader::new(fd);
    let mut rng = AesState::new();
    let mut rng_kem = AesState::new();

    // first record in a response file is empty (e.g. “# ntruhps2048509\n”)
    // hence, skip it
    let mut expected = Testcase::new();
    expected.read_from_file(&mut reader)?;

    // create KATNUM testcase seeds
    for t in 0..KATNUM {
        let mut expected = Testcase::new();
        expected.read_from_file(&mut reader)?;

        rng.randombytes_init(expected.seed);
        rng_kem.randombytes_init(expected.seed_kem);

        let mut actual = Testcase::with_seed(t, &expected.seed, &expected.seed_kem);

        let mut pk_buf;
        #[cfg(feature = "alloc")]
        {
            pk_buf = Box::new([0u8; CRYPTO_PUBLICKEYBYTES]);
        }
        #[cfg(not(feature = "alloc"))]
        {
            pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
        }
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

        let (pk_kem, sk_kem) = keypair_boxed(&mut rng_kem);
        let (ct_kem, ss_kem) = ClassicMcEliece.try_encap(&mut rng_kem, &pk_kem).unwrap();
        let ss2_kem = sk_kem.try_decap(&ct_kem).unwrap();

        actual.pk_kem = *pk_kem.as_array();
        actual.sk_kem = *sk_kem.as_array();
        assert_eq!(ss_kem.as_bytes(), ss2_kem.as_bytes());
        actual.ss_kem.copy_from_slice(ss_kem.as_bytes());
        actual.ct_kem.copy_from_slice(ct_kem.as_ref());

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
        assert_eq!(
            expected.pk_kem, actual.pk_kem,
            "public keys of testcase {} don't match",
            expected.count
        );
        assert_eq!(
            expected.sk_kem, actual.sk_kem,
            "secret keys of testcase {} don't match",
            expected.count
        );
        assert_eq!(
            expected.ct_kem, actual.ct_kem,
            "ciphertexts of testcase {} don't match",
            expected.count
        );
        assert_eq!(
            expected.ss_kem, actual.ss_kem,
            "shared secrets of testcase {} don't match",
            expected.count
        );
    }

    Ok(())
}

#[test]
fn katkem() {
    use std::env::{self, Args};

    fn run_katkem(mut args: Args) {
        match args.len() {
            3 => {
                args.next().unwrap();
                args.next().unwrap();
                let rsp_file = args.next().unwrap();
                verify(&rsp_file).unwrap();

                println!("verification successful.");
            }

            4 => {
                args.next().unwrap();
                args.next().unwrap();

                let req_file = args.next().unwrap();
                let rsp_file = args.next().unwrap();

                create_request_file(&req_file).unwrap();
                println!("request file '{}' created.", &req_file);

                create_response_file(&rsp_file).unwrap();
                println!("response file '{}' created.", &rsp_file);
            }

            _ => {
                eprintln!("usage: ./PQCgenKAT_kem <request:filepath> <response:filepath>");
                eprintln!("  generate a request and response file\n");
                eprintln!("usage: ./PQCgenKAT_kem <response:filepath>");
                eprintln!("  verify the given response file\n");
                eprintln!("wrong number of arguments");
                assert!(false);
            }
        }
    }

    std::thread::Builder::new()
        .stack_size(20 * 1024 * 1024)
        .spawn(|| run_katkem(env::args()))
        .unwrap()
        .join()
        .unwrap();
}

#[test]
#[cfg(feature = "zeroize")]
fn zeroize() {
    fn run_zeroize() {
        use crate::{keypair, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};

        let mut pk_buffer = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk_buffer = [5u8; CRYPTO_SECRETKEYBYTES];
        let mut rng = rand::thread_rng();

        let zeroed_key = [0; CRYPTO_SECRETKEYBYTES];

        let (_, secret_key) = keypair(&mut pk_buffer, &mut sk_buffer, &mut rng);
        drop(secret_key);

        assert_eq!(zeroed_key, sk_buffer);
    }

    std::thread::Builder::new()
        // Use a large enough stack size to run_zeroize all kem variants with the key buffers on the stack.
        .stack_size(4 * 1024 * 1024)
        .spawn(run_zeroize)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
#[cfg(feature = "mceliece8192128f")]
fn crypto_alloc_api_keypair() {
    use crate::{keypair_boxed, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};

    let entropy_input = <[u8; 48]>::try_from(
        TestData::new()
            .u8vec("mceliece8192128f_operations_entropy_input")
            .as_slice(),
    )
    .unwrap();

    let compare_sk = TestData::new().u8vec("mceliece8192128f_operations_sk_expected");
    assert_eq!(compare_sk.len(), CRYPTO_SECRETKEYBYTES);

    let compare_pk = TestData::new().u8vec("mceliece8192128f_operations_pk_expected");
    assert_eq!(compare_pk.len(), CRYPTO_PUBLICKEYBYTES);

    let mut rng_state = crate::nist_aes_rng::AesState::new();
    rng_state.randombytes_init(entropy_input);

    let (pk, sk) = keypair_boxed(&mut rng_state);

    assert_eq!(compare_sk.as_slice(), sk.0.as_ref());
    assert_eq!(compare_pk.as_slice(), pk.0.as_ref());
}

#[test]
fn testdata_sanity_check() {
    assert_eq!(
        TestData::new().u8vec("sanity_check"),
        [0x01, 0x23, 0x45, 0x67].to_vec()
    );
    assert_eq!(
        TestData::new().u16vec("sanity_check"),
        [0x0123, 0x4567].to_vec()
    );
    assert_eq!(
        TestData::new().u32vec("sanity_check"),
        [0x01234567].to_vec()
    );
}
