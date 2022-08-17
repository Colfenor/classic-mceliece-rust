//! This is a pure-rust safe-rust implementation of the Classic McEliece post-quantum scheme.
//!
//! An example is provided to illustrate the API. Be aware that this documentation is generated
//! for one specific variant (among ten). Thus the array lengths will be different if you specify
//! a different variant via feature flags.

#![no_std]
#![forbid(unsafe_code)]

mod api;
mod benes;
mod bm;
mod controlbits;
mod crypto_hash;
mod decrypt;
mod encrypt;
mod gf;
mod int32_sort;
pub(crate) mod operations;
mod params;
mod pk_gen;
mod root;
mod sk_gen;
mod synd;
mod transpose;
mod uint64_sort;
mod util;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "kem")]
pub use api::kem_api::ClassicMcEliece;
pub use api::{Ciphertext, PublicKey, SecretKey};

#[cfg(test)]
mod nist_aes_rng;
#[cfg(test)]
#[macro_use]
extern crate std;
#[cfg(test)]
use std::vec::Vec;

#[cfg(feature = "alloc")]
pub use api::keypair_boxed;
pub use api::{decaps, encaps, keypair};
pub use api::{
    CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_PRIMITIVE, CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES,
};

mod macros {
    /// This macro(A, B, C, T) allows to get “&A[B..B+C]” of type “&[T]” as type “&[T; C]”.
    /// The default type T is u8 and “mut A” instead of “A” returns a mutable reference.
    macro_rules! sub {
        ($var:expr, $offset:expr, $len:expr) => {{
            <&[u8; $len]>::try_from(&$var[$offset..($offset + $len)])
                .expect("slice has the correct length")
        }};
        (mut $var:expr, $offset:expr, $len:expr) => {{
            <&mut [u8; $len]>::try_from(&mut $var[$offset..($offset + $len)])
                .expect("slice has the correct length")
        }};
        ($var:expr, $offset:expr, $len:expr, $t:ty) => {{
            <&[$t; $len]>::try_from(&$var[$offset..($offset + $len)])
                .expect("slice has the correct length")
        }};
        (mut $var:expr, $offset:expr, $len:expr, $t:ty) => {{
            <&mut [$t; $len]>::try_from(&mut $var[$offset..($offset + $len)])
                .expect("slice has the correct length")
        }};
    }

    pub(crate) use sub;
}

// Test specifics below.

#[cfg(test)]
macro_rules! impl_parser_per_type {
    ($name:ident, $bitsize:expr, $t:ty) => {
        /// Parses a testdata file and returns a vector of $ty stored for the given `search_key`.
        /// The value is parsed in big-endian order.
        ///
        /// I started to write a zero-allocation parser, but it takes many lines of code.
        /// This design allocates, but can be comprehended much easier.
        fn $name(&self, search_key: &str) -> Vec<$t> {
            use std::convert::TryInto;
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
                        _ => {}
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
                    let element = &bytes[bytes_per_element * idx..bytes_per_element * (idx + 1)];
                    elements.push(<$t>::from_be_bytes(
                        element.try_into().expect("invalid slice length"),
                    ));
                }
                return elements;
            }

            panic!("search_key '{}' not found in testdata.txt", search_key);
        }
    };
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
    //impl_parser_per_type!(i8vec, 8, i8);
    #[cfg(any(
        feature = "mceliece348864",
        feature = "mceliece6960119",
        feature = "mceliece8192128f"
    ))]
    impl_parser_per_type!(i16vec, 16, i16);
    //impl_parser_per_type!(i32vec, 32, i32);
    //impl_parser_per_type!(i64vec, 64, i64);
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

#[cfg(doctest)]
mod test_readme {
    macro_rules! external_doc_test {
        ($x:expr) => {
            #[doc = $x]
            extern "C" {}
        };
    }

    external_doc_test!(include_str!("../README.md"));
}
