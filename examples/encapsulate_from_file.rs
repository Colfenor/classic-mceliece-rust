//! Stream a public key from a file using a fixed-size buffer.
//!
//! Run:
//!   cargo run --example encapsulate_from_file --features mceliece348864
//! Or:
//!   ./scripts/run_example.sh encapsulate_from_file mceliece348864
//!
//! This example auto-generates missing key files when run directly.
//!
//! The public key file must contain `CRYPTO_PUBLICKEYBYTES` bytes in row-major order.
//! A matching secret key file is used to validate decapsulation.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
#[cfg(feature = "embedded-workspace")]
use classic_mceliece_rust::DecapsulationWorkspace;
use classic_mceliece_rust::{
    decapsulate, keypair_boxed,
    streaming::{encapsulate_from_reader, PublicKeyReader},
    SecretKey, CRYPTO_BYTES, CRYPTO_PRIMITIVE, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
};
use rand::{rngs::StdRng, SeedableRng};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use std::alloc::{GlobalAlloc, Layout, System};
use std::error::Error;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

struct TrackingAllocator;

static CURRENT_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static PEAK_ALLOCATED: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static GLOBAL_ALLOCATOR: TrackingAllocator = TrackingAllocator;

impl TrackingAllocator {
    fn record_alloc(size: usize) {
        let new_current = CURRENT_ALLOCATED.fetch_add(size, Ordering::Relaxed) + size;
        let mut peak = PEAK_ALLOCATED.load(Ordering::Relaxed);
        while new_current > peak {
            match PEAK_ALLOCATED.compare_exchange(
                peak,
                new_current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(updated) => peak = updated,
            }
        }
    }

    fn record_dealloc(size: usize) {
        CURRENT_ALLOCATED.fetch_sub(size, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            Self::record_alloc(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            Self::record_alloc(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        Self::record_dealloc(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            let old_size = layout.size();
            if new_size > old_size {
                Self::record_alloc(new_size - old_size);
            } else if old_size > new_size {
                Self::record_dealloc(old_size - new_size);
            }
        }
        new_ptr
    }
}

const DEFAULT_FILE_BUFFER_BYTES: usize = 16 * 1024;
const MESSAGE_LEN: usize = 11;
const MESSAGE: [u8; MESSAGE_LEN] = *b"Hello World";

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

struct FilePublicKeyReader<'a> {
    file: File,
    buffer: &'a mut [u8],
    buf_pos: usize,
    buf_len: usize,
    max_buffered: usize,
    total_copied: usize,
}

impl<'a> FilePublicKeyReader<'a> {
    fn new(file: File, buffer: &'a mut [u8]) -> Self {
        Self {
            file,
            buffer,
            buf_pos: 0,
            buf_len: 0,
            max_buffered: 0,
            total_copied: 0,
        }
    }

    fn refill(&mut self) -> io::Result<()> {
        self.buf_len = self.file.read(self.buffer)?;
        self.buf_pos = 0;
        self.max_buffered = self.max_buffered.max(self.buf_len);
        if self.buf_len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "public key file too short",
            ));
        }
        Ok(())
    }

    fn buffer_bytes(&self) -> usize {
        self.buffer.len()
    }

    fn max_buffered(&self) -> usize {
        self.max_buffered
    }

    fn total_copied(&self) -> usize {
        self.total_copied
    }
}

impl PublicKeyReader for FilePublicKeyReader<'_> {
    type Error = io::Error;

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
            self.total_copied += to_copy;
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), Self::Error> {
        if self.buf_pos < self.buf_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "public key file too long",
            ));
        }

        let mut extra = [0u8; 1];
        let read = self.file.read(&mut extra)?;
        if read == 0 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "public key file too long",
            ))
        }
    }

    fn invalid_padding(&self) -> Self::Error {
        io::Error::new(io::ErrorKind::InvalidData, "public key padding invalid")
    }
}

fn ensure_keypair_files(pk_path: &Path, sk_path: &Path) -> Result<(), Box<dyn Error>> {
    if pk_path.exists() && sk_path.exists() {
        return Ok(());
    }

    let mut rng = StdRng::from_seed([0xA5; 32]);
    let (public_key, secret_key) = keypair_boxed(&mut rng);
    std::fs::write(pk_path, public_key.as_array())?;
    std::fs::write(sk_path, secret_key.as_array())?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let default_pk_path = format!(
        "{}/examples/keys/public_key_{}.bin",
        env!("CARGO_MANIFEST_DIR"),
        CRYPTO_PRIMITIVE
    );
    let default_sk_path = format!(
        "{}/examples/keys/secret_key_{}.bin",
        env!("CARGO_MANIFEST_DIR"),
        CRYPTO_PRIMITIVE
    );
    let mut args = std::env::args().skip(1);
    let pk_path = args.next().unwrap_or(default_pk_path);
    let sk_path = args.next().unwrap_or(default_sk_path);
    let pk_path_ref = Path::new(&pk_path);
    let sk_path_ref = Path::new(&sk_path);

    ensure_keypair_files(pk_path_ref, sk_path_ref)?;
    let file = File::open(pk_path_ref)?;
    let mut buffer = vec![0u8; DEFAULT_FILE_BUFFER_BYTES];
    let mut reader = FilePublicKeyReader::new(file, buffer.as_mut_slice());

    let mut shared_secret_buf = [0u8; CRYPTO_BYTES];
    let mut rng = StdRng::from_seed([0x11; 32]);

    let (ciphertext, shared_secret) =
        encapsulate_from_reader(&mut reader, &mut shared_secret_buf, &mut rng)?;

    let mut sk_buf = [0u8; CRYPTO_SECRETKEYBYTES];
    let mut sk_file = File::open(sk_path_ref)?;
    sk_file.read_exact(&mut sk_buf)?;
    let secret_key = SecretKey::from(&mut sk_buf);

    let mut ss2_buf = [0u8; CRYPTO_BYTES];
    #[cfg(feature = "embedded-workspace")]
    let ss2 = {
        let mut workspace = DecapsulationWorkspace::new();
        decapsulate(&ciphertext, &secret_key, &mut ss2_buf, &mut workspace)
    };
    #[cfg(not(feature = "embedded-workspace"))]
    let ss2 = decapsulate(&ciphertext, &secret_key, &mut ss2_buf);
    if shared_secret.as_array() != ss2.as_array() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::Other,
            "shared secret mismatch",
        )));
    }

    let decrypted_message =
        aes256_encrypt_decrypt(shared_secret.as_array(), ss2.as_array(), &MESSAGE);
    if decrypted_message != MESSAGE {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::Other,
            "message mismatch",
        )));
    }

    println!("public key bytes: {}", CRYPTO_PUBLICKEYBYTES);
    println!("public key bytes read: {}", reader.total_copied());
    println!("file buffer bytes: {}", reader.buffer_bytes());
    println!("max buffered bytes: {}", reader.max_buffered());
    println!("public key file: {}", pk_path);
    println!("secret key file: {}", sk_path);
    println!(
        "live allocated bytes: {}",
        CURRENT_ALLOCATED.load(Ordering::Relaxed)
    );
    println!(
        "peak live allocated bytes: {}",
        PEAK_ALLOCATED.load(Ordering::Relaxed)
    );

    Ok(())
}
