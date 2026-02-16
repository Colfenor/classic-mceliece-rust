//! No-std friendly example that reads a public key from a static buffer.
//!
//! Run:
//!   cargo run --example encapsulate_static_no_std --features "mceliece348864 example-embedded-keys"
//! Or:
//!   ./scripts/run_example.sh encapsulate_static_no_std mceliece348864
//!
//! The key files are loaded via `include_bytes!`. Generate them first via
//! `./scripts/run_example.sh encapsulate_from_file <variant>`.
//!
//! The bytes are loaded from `examples/keys/public_key_<variant>.bin` and
//! `examples/keys/secret_key_<variant>.bin`.
//! Replace those files with your actual key bytes stored in ROM/flash.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
#[cfg(feature = "embedded-workspace")]
use classic_mceliece_rust::DecapsulationWorkspace;
use classic_mceliece_rust::{
    decapsulate,
    streaming::{encapsulate_from_reader, PublicKeyReader},
    SecretKey, CRYPTO_BYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
};
use rand::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

const STATIC_BUFFER_BYTES: usize = 16 * 1024;
const MESSAGE_LEN: usize = 11;
const MESSAGE: [u8; MESSAGE_LEN] = *b"Hello World";

static mut STATIC_BUFFER: [u8; STATIC_BUFFER_BYTES] = [0u8; STATIC_BUFFER_BYTES];

#[cfg(feature = "mceliece348864")]
static PUBLIC_KEY_BYTES: [u8; CRYPTO_PUBLICKEYBYTES] =
    *include_bytes!("keys/public_key_mceliece348864.bin");
#[cfg(feature = "mceliece348864f")]
static PUBLIC_KEY_BYTES: [u8; CRYPTO_PUBLICKEYBYTES] =
    *include_bytes!("keys/public_key_mceliece348864f.bin");
#[cfg(feature = "mceliece460896")]
static PUBLIC_KEY_BYTES: [u8; CRYPTO_PUBLICKEYBYTES] =
    *include_bytes!("keys/public_key_mceliece460896.bin");
#[cfg(feature = "mceliece460896f")]
static PUBLIC_KEY_BYTES: [u8; CRYPTO_PUBLICKEYBYTES] =
    *include_bytes!("keys/public_key_mceliece460896f.bin");
#[cfg(feature = "mceliece6688128")]
static PUBLIC_KEY_BYTES: [u8; CRYPTO_PUBLICKEYBYTES] =
    *include_bytes!("keys/public_key_mceliece6688128.bin");
#[cfg(feature = "mceliece6688128f")]
static PUBLIC_KEY_BYTES: [u8; CRYPTO_PUBLICKEYBYTES] =
    *include_bytes!("keys/public_key_mceliece6688128f.bin");
#[cfg(feature = "mceliece6960119")]
static PUBLIC_KEY_BYTES: [u8; CRYPTO_PUBLICKEYBYTES] =
    *include_bytes!("keys/public_key_mceliece6960119.bin");
#[cfg(feature = "mceliece6960119f")]
static PUBLIC_KEY_BYTES: [u8; CRYPTO_PUBLICKEYBYTES] =
    *include_bytes!("keys/public_key_mceliece6960119f.bin");
#[cfg(feature = "mceliece8192128")]
static PUBLIC_KEY_BYTES: [u8; CRYPTO_PUBLICKEYBYTES] =
    *include_bytes!("keys/public_key_mceliece8192128.bin");
#[cfg(feature = "mceliece8192128f")]
static PUBLIC_KEY_BYTES: [u8; CRYPTO_PUBLICKEYBYTES] =
    *include_bytes!("keys/public_key_mceliece8192128f.bin");

#[cfg(feature = "mceliece348864")]
static mut SECRET_KEY_BYTES: [u8; CRYPTO_SECRETKEYBYTES] =
    *include_bytes!("keys/secret_key_mceliece348864.bin");
#[cfg(feature = "mceliece348864f")]
static mut SECRET_KEY_BYTES: [u8; CRYPTO_SECRETKEYBYTES] =
    *include_bytes!("keys/secret_key_mceliece348864f.bin");
#[cfg(feature = "mceliece460896")]
static mut SECRET_KEY_BYTES: [u8; CRYPTO_SECRETKEYBYTES] =
    *include_bytes!("keys/secret_key_mceliece460896.bin");
#[cfg(feature = "mceliece460896f")]
static mut SECRET_KEY_BYTES: [u8; CRYPTO_SECRETKEYBYTES] =
    *include_bytes!("keys/secret_key_mceliece460896f.bin");
#[cfg(feature = "mceliece6688128")]
static mut SECRET_KEY_BYTES: [u8; CRYPTO_SECRETKEYBYTES] =
    *include_bytes!("keys/secret_key_mceliece6688128.bin");
#[cfg(feature = "mceliece6688128f")]
static mut SECRET_KEY_BYTES: [u8; CRYPTO_SECRETKEYBYTES] =
    *include_bytes!("keys/secret_key_mceliece6688128f.bin");
#[cfg(feature = "mceliece6960119")]
static mut SECRET_KEY_BYTES: [u8; CRYPTO_SECRETKEYBYTES] =
    *include_bytes!("keys/secret_key_mceliece6960119.bin");
#[cfg(feature = "mceliece6960119f")]
static mut SECRET_KEY_BYTES: [u8; CRYPTO_SECRETKEYBYTES] =
    *include_bytes!("keys/secret_key_mceliece6960119f.bin");
#[cfg(feature = "mceliece8192128")]
static mut SECRET_KEY_BYTES: [u8; CRYPTO_SECRETKEYBYTES] =
    *include_bytes!("keys/secret_key_mceliece8192128.bin");
#[cfg(feature = "mceliece8192128f")]
static mut SECRET_KEY_BYTES: [u8; CRYPTO_SECRETKEYBYTES] =
    *include_bytes!("keys/secret_key_mceliece8192128f.bin");

struct StaticStorageReader {
    storage_pos: usize,
    buf_pos: usize,
    buf_len: usize,
    buffer: &'static mut [u8],
}

impl StaticStorageReader {
    fn new(buffer: &'static mut [u8]) -> Self {
        Self {
            storage_pos: 0,
            buf_pos: 0,
            buf_len: 0,
            buffer,
        }
    }

    fn refill(&mut self) -> Result<(), ()> {
        if self.storage_pos >= PUBLIC_KEY_BYTES.len() {
            return Err(());
        }
        let remaining = PUBLIC_KEY_BYTES.len() - self.storage_pos;
        let to_copy = remaining.min(self.buffer.len());
        self.buffer[..to_copy]
            .copy_from_slice(&PUBLIC_KEY_BYTES[self.storage_pos..self.storage_pos + to_copy]);
        self.storage_pos += to_copy;
        self.buf_pos = 0;
        self.buf_len = to_copy;
        Ok(())
    }
}

impl PublicKeyReader for StaticStorageReader {
    type Error = ();

    fn read_exact(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
        let mut written = 0;
        while written < out.len() {
            if self.buf_pos == self.buf_len {
                self.refill()?;
            }

            let available = self.buf_len - self.buf_pos;
            let to_copy = (out.len() - written).min(available);
            out[written..written + to_copy]
                .copy_from_slice(&self.buffer[self.buf_pos..self.buf_pos + to_copy]);
            self.buf_pos += to_copy;
            written += to_copy;
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), Self::Error> {
        if self.storage_pos == PUBLIC_KEY_BYTES.len() && self.buf_pos == self.buf_len {
            Ok(())
        } else {
            Err(())
        }
    }

    fn invalid_padding(&self) -> Self::Error {
        ()
    }
}

/// Small deterministic RNG for no-std demo runs.
///
/// This is *not* cryptographically secure, but unlike a simple counter it
/// provides enough diffusion to avoid pathological rejection-loop behavior in
/// `gen_e`.
struct DemoRng(u64);

impl RngCore for DemoRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        // xorshift64* (deterministic, fast, non-cryptographic)
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&bytes[..len]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for DemoRng {}

fn derive_aes_key_nonce(shared_secret: &[u8; CRYPTO_BYTES]) -> ([u8; 32], [u8; 16]) {
    let mut shake = Shake256::default();
    shake.update(shared_secret);
    let mut reader = shake.finalize_xof();
    let mut out = [0u8; 48];
    reader.read(&mut out);
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&out[32..]);
    (key, nonce)
}

fn aes256_ctr_xor<const N: usize>(
    key: &[u8; 32],
    nonce: &[u8; 16],
    input: &[u8; N],
    output: &mut [u8; N],
) {
    let cipher = Aes256::new(key.into());
    let mut counter = u128::from_be_bytes(*nonce);
    for (chunk_out, chunk_in) in output.chunks_mut(16).zip(input.chunks(16)) {
        let mut block = counter.to_be_bytes();
        cipher.encrypt_block((&mut block).into());
        for i in 0..chunk_in.len() {
            chunk_out[i] = chunk_in[i] ^ block[i];
        }
        counter = counter.wrapping_add(1);
    }
}

fn aes256_encrypt_decrypt<const N: usize>(
    shared_secret_enc: &[u8; CRYPTO_BYTES],
    shared_secret_dec: &[u8; CRYPTO_BYTES],
    plaintext: &[u8; N],
) -> [u8; N] {
    let (enc_key, enc_nonce) = derive_aes_key_nonce(shared_secret_enc);
    let (dec_key, dec_nonce) = derive_aes_key_nonce(shared_secret_dec);
    let mut ciphertext = [0u8; N];
    aes256_ctr_xor(&enc_key, &enc_nonce, plaintext, &mut ciphertext);
    let mut decrypted = [0u8; N];
    aes256_ctr_xor(&dec_key, &dec_nonce, &ciphertext, &mut decrypted);
    decrypted
}

fn main() {
    #[allow(static_mut_refs)]
    let mut reader = StaticStorageReader::new(unsafe { &mut STATIC_BUFFER });
    let mut shared_secret_buf = [0u8; CRYPTO_BYTES];
    let mut rng = DemoRng(0x1234_5678_9ABC_DEF0);

    let (ciphertext, shared_secret) =
        encapsulate_from_reader(&mut reader, &mut shared_secret_buf, &mut rng)
            .expect("encapsulation failed");

    #[allow(static_mut_refs)]
    let secret_key = SecretKey::from(unsafe { &mut SECRET_KEY_BYTES });
    let mut ss2_buf = [0u8; CRYPTO_BYTES];
    #[cfg(feature = "embedded-workspace")]
    let ss2 = {
        let mut workspace = DecapsulationWorkspace::new();
        decapsulate(&ciphertext, &secret_key, &mut ss2_buf, &mut workspace)
    };
    #[cfg(not(feature = "embedded-workspace"))]
    let ss2 = decapsulate(&ciphertext, &secret_key, &mut ss2_buf);
    if shared_secret.as_array() != ss2.as_array() {
        panic!("shared secret mismatch");
    }

    let decrypted_message =
        aes256_encrypt_decrypt(shared_secret.as_array(), ss2.as_array(), &MESSAGE);
    if decrypted_message != MESSAGE {
        panic!("message mismatch");
    }
}
