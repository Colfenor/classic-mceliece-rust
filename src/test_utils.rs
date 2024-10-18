#![cfg(test)]

macro_rules! impl_parser_per_type {
    ($name:ident, $bitsize:expr, $t:ty) => {
        /// Parses a testdata file and returns a vector of $ty stored for the given `search_key`.
        /// The value is parsed in big-endian order.
        ///
        /// I started to write a zero-allocation parser, but it takes many lines of code.
        /// This design allocates, but can be comprehended much easier.
        pub(crate) fn $name(&self, search_key: &str) -> std::vec::Vec<$t> {
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
                let mut elements = std::vec::Vec::<$t>::with_capacity(elements_count);
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

pub(crate) struct TestData {
    data: &'static [u8],
}

impl TestData {
    pub(crate) fn new() -> TestData {
        let bytes = include_bytes!("../data/testdata.txt");
        TestData { data: bytes }
    }

    impl_parser_per_type!(u8vec, 8, u8);
    impl_parser_per_type!(u16vec, 16, u16);
    #[cfg(feature = "kem")]
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
