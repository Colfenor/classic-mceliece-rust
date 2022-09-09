# classic-mceliece-rust

This is a pure-rust safe-rust implementation of the Classic McEliece post-quantum scheme.

* Classic McEliece is a code-based key encapsulation mechanism (KEM)
* The implementation is based on the Classic McEliece reference implementation of [NIST round 3](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions)
* The implementation does not utilize any concurrency techniques (SIMD/threading/…, except maybe auto-vectorization on your CPU)
* It depends on `sha3` as SHA-3 implementation and `aes` as AES block cipher (used as RNG) implementation
* It passes the 100 testcases of the C reference implementation
* It implements all 10 variants of the Classic McEliece KEM
* The implementation takes between 100 milliseconds (`mceliece348864`) and 500 milliseconds (`mceliece8192128f`) to run on a modern computer
* The implementation is constant-time on software instruction level
* The random number generator is based on AES256 in counter mode
* First described in 1978, the cryptographic scheme has a rich history in security analysis. Its large public key size, however, often limits adoption.

The 10 variants have the following designated identifiers:

* `mceliece348864`
* `mceliece348864f`
* `mceliece460896`
* `mceliece460896f`
* `mceliece6688128`
* `mceliece6688128f`
* `mceliece6960119`
* `mceliece6960119f`
* `mceliece8192128`
* `mceliece8192128f`

## Who should use it?

Anyone, how wants to use Classic McEliece to negotiate a key between two parties.

## How does one use it storing keys on the heap (default feature `alloc`)?

Add this to your `Cargo.toml`:
```toml
[dependencies]
classic-mceliece-rust = "2.0"
```

To use a specific Classic McEliece variant, you need to import it with the corresponding feature flag:

```toml
[dependencies]
classic-mceliece-rust = { version = "2.0", features = ["mceliece6960119"] }
```

Assuming this dependency, the simplest and most ergonomic way of using the library
is with heap allocated keys and the `*_boxed` KEM step functions. First, we import them:

```rust
use classic_mceliece_rust::{keypair_boxed, encapsulate_boxed, decapsulate_boxed};
```

Followingly, we run the KEM and provide generated keys accordingly.
Here, we consider an example where we run it in a separate thread (be aware that the example also depends on the rand crate):

```rust
fn run_kem() {
  let mut rng = rand::thread_rng();

  // Alice computes the keypair
  let (public_key, secret_key) = keypair_boxed(&mut rng);

  // Send `secret_key` over to Bob.
  // Bob computes the shared secret and a ciphertext
  let (ciphertext, shared_secret_bob) = encapsulate_boxed(&public_key, &mut rng);

  // Send `ciphertext` back to Alice.
  // Alice decapsulates the ciphertext...
  let shared_secret_alice = decapsulate_boxed(&ciphertext, &secret_key);

  // ... and ends up with the same key material as Bob.
  assert_eq!(shared_secret_bob.as_array(), shared_secret_alice.as_array());
}

fn main() {
  std::thread::Builder::new()
    // This library needs quite a lot of stack space to work
    .stack_size(2 * 1024 * 1024)
    .spawn(run_kem)
    .unwrap()
    .join()
    .unwrap();
}
```

Pay attention that public keys in Classic McEliece are huge (between 255 KB and 1.3 MB). As a result, running the algorithm requires a lot of memory. You need to consider where you store it. In case of this API, the advantages are …

* you don't need to handle the memory manually
* on Windows, the call to `keypair` uses more stack than is available by default. Such stack size limitations can be avoided with the heap-allocation API (see Windows remark below).

## How does one use it storing keys on the stack (disabled feature `alloc`)?

The other option is that you exclude the heap-allocation API and use the provided stack-allocation API. Its advantages are:

* stack allocation also works in a `no_std` environment.
* on some microcontroller platforms, a heap is not available.
* stack (de-)allocation in general is faster than heap (de-)allocation

Thus, in this section we want to show you how to use this API without the heap. For this, you need to disable feature `alloc` which is enabled per default (this line retains default feature `zeroize` but removes default feature `alloc`):

```toml
classic-mceliece-rust = { version = "2.0", default-features = false, features = ["zeroize"] }
```

How does one use the API then (be aware that the example also depends on the rand crate)?

```rust
use classic_mceliece_rust::{keypair, encapsulate, decapsulate};
use classic_mceliece_rust::{CRYPTO_BYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};

fn main() {
  let mut rng = rand::thread_rng();

  // Please mind that `public_key_buf` is very large.
  let mut public_key_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
  let mut secret_key_buf = [0u8; CRYPTO_SECRETKEYBYTES];
  let (public_key, secret_key) = keypair(&mut public_key_buf, &mut secret_key_buf, &mut rng);

  let mut shared_secret_bob_buf = [0u8; CRYPTO_BYTES];
  let (ciphertext, shared_secret_bob) = encapsulate(&public_key, &mut shared_secret_bob_buf, &mut rng);

  let mut shared_secret_alice_buf = [0u8; CRYPTO_BYTES];
  let shared_secret_alice = decapsulate(&ciphertext, &secret_key, &mut shared_secret_alice_buf);

  assert_eq!(shared_secret_bob.as_array(), shared_secret_alice.as_array());
}
```

Here, you can see how the keys are allocated explicitly.

#### A remark on Windows

If you want your program to be portable with stack allocation and not unexpectedly crash, you should probably run the entire key exchange in a dedicated thread with a large enough stack size. This code snippet shows the idea:

```rust,no_run
std::thread::Builder::new()
    .stack_size(4 * 1024 * 1024)
    .spawn(|| {/* Run the KEM here */})
    .unwrap();
```

### Feature kem: RustCrypto APIs

If the `kem` feature is enabled, key encapsulation and decapsulation can also be done via
the standard traits in the `kem` crate.

### Feature zeroize: Clear out secrets from memory

If the `zeroize` feature is enabled (it is by default), all key types that contain anything secret
implements `Zeroize` and `ZeroizeOnDrop`. This makes them clear their memory when they go out of
scope, and lowers the risk of secret key material leaking in one way or another.

Please mind that this of course makes any buffers you pass into the library useless for reading
out the key from. Instead of trying to fetch the key material from the buffers you pass in,
get it from the `as_array` method.

```rust
#[cfg(not(windows))] {
    use classic_mceliece_rust::keypair;
    use classic_mceliece_rust::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};

    let mut rng = rand::thread_rng();

    let mut pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
    // Initialize to non-zero to show that it has been set to zero by the drop later
    let mut sk_buf = [255u8; CRYPTO_SECRETKEYBYTES];

    // This is the WRONG way of accessing your keys. The buffer will
    // be cleared once the `PrivateKey` returned from `keypair` goes out of scope.
    // You should not rely on that array for anything except providing a temporary storage
    // location to this library.
    #[cfg(feature = "zeroize")]
    {
        let (_, secret_key) = keypair(&mut pk_buf, &mut sk_buf, &mut rng);
        drop(secret_key);
        // Ouch! The array only has zeroes now.
        assert_eq!(sk_buf, [0; CRYPTO_SECRETKEYBYTES]);
    }

    // Correct way of getting the secret key bytes if you do need them. However,
    // if you want the secrets to stay secret, you should try to not read them out of their
    // storage at all
    {
        let (_, secret_key) = keypair(&mut pk_buf, &mut sk_buf, &mut rng);
        assert_ne!(secret_key.as_array(), &[0; CRYPTO_SECRETKEYBYTES]);
    }
}
```

## How does one run it?

This library comes with two examples:

```bash
$ cargo run --example basic
```

The output annotates messages with Alice/Bob to illustrate which data is processed by which party.
The `katkem` example implements the classic request/response file structure which is part of the NIST PQC framework.

```bash
$ cargo run --example katkem PQCkemKAT_935.req PQCkemKAT_935.rsp
$ cargo run --example katkem PQCkemKAT_935.rsp
```

The different variants can be enabled through feature flags:

```bash
$ cargo run --example katkem --features mceliece6960119 -- PQCkemKAT_1450.req PQCkemKAT_1450.rsp
```

`mceliece348864` is the default variant. You cannot enable two variants simultaneously.

## How fast is it?

All data uses clock cycles as unit (the smaller the better).
The rust implementation yielded the following runtime results:

<table>
  <thead>
    <tr><td></td><td>complete KEM</td><td>keypair</td><td>enc</td><td>dec</td></tr>
  </thead><tbody>
    <tr><td>mceliece348864</td><td>460,062,191</td><td>439,682,143</td><td>222,424</td><td>42,046,357</td></tr>
    <tr><td>mceliece348864f</td><td>244,943,900</td><td>203,564,820</td><td>215,971</td><td>41,648,773</td></tr>
    <tr><td>mceliece460896</td><td>1,326,425,784</td><td>1,434,864,061</td><td>487,522</td><td>111,547,716</td></tr>
    <tr><td>mceliece460896f</td><td>789,636,856</td><td>652,117,200</td><td>553,301</td><td>106,521,703</td></tr>
    <tr><td>mceliece6688128</td><td>3,188,205,266</td><td>2,596,052,574</td><td>785,763</td><td>202,774,928</td></tr>
    <tr><td>mceliece6688128f</td><td>1,236,809,020</td><td>1,059,087,715</td><td>826,899</td><td>203,907,226</td></tr>
    <tr><td>mceliece6960119</td><td>2,639,852,573</td><td>2,532,146,126</td><td>3,864,285</td><td>203,959,009</td></tr>
    <tr><td>mceliece6960119f</td><td>1,165,079,187</td><td>965,134,546</td><td>3,416,795</td><td>197,089,546</td></tr>
    <tr><td>mceliece8192128</td><td>3,129,183,262</td><td>2,754,933,130</td><td>965,822</td><td>247,083,745</td></tr>
    <tr><td>mceliece8192128f</td><td>1,342,438,451</td><td>1,150,297,595</td><td>1,068,317</td><td>242,545,160</td></tr>
  </tbody>
</table>

The C reference implementation yielded the following runtime results:

<table>
  <thead>
    <tr><td></td><td>complete KEM</td><td>keypair</td><td>enc</td><td>dec</td></tr>
  </thead><tbody>
    <tr><td>mceliece348864</td><td>434,103,000</td><td>437,187,000</td><td>187,557</td><td>73,801,300</td></tr>
    <tr><td>mceliece348864f</td><td>252,423,000</td><td>180,235,000</td><td>189,522</td><td>73,668,000</td></tr>
    <tr><td>mceliece460896</td><td>760,993,000</td><td>894,497,000</td><td>298,041</td><td>154,507,000</td></tr>
    <tr><td>mceliece460896f</td><td>606,225,000</td><td>44,906,000</td><td>297,743</td><td>154,013,000</td></tr>
    <tr><td>mceliece6688128</td><td>1,568,900,000</td><td>1,780,660,000</td><td>425,504</td><td>29,575,000</td></tr>
    <tr><td>mceliece6688128f</td><td>109,471,000</td><td>760,298,000</td><td>414,358</td><td>298,173,000</td></tr>
    <tr><td>mceliece6960119</td><td>3,405,730,000</td><td>1,694,410,000</td><td>840,598</td><td>287,154,000</td></tr>
    <tr><td>mceliece6960119f</td><td>1,311,130,000</td><td>942,987,000</td><td>984,660</td><td>303,543,000</td></tr>
    <tr><td>mceliece8192128</td><td>1,635,550,000</td><td>760,619,000</td><td>428,112</td><td>361,999,000</td></tr>
    <tr><td>mceliece8192128f</td><td>1,772,530,000</td><td>1,222,720,000</td><td>534,503</td><td>392,729,000</td></tr>
  </tbody>
</table>

The tests were done on a Lenovo Thinkpad x260 (Intel Core i5-6200U CPU @ 2.30GHz). In the case of rust, [criterion 0.3.5](https://crates.io/crates/criterion) has been used as given in `benches/` and in case of C, Google's [benchmark](https://github.com/google/benchmark/blob/v1.6.1/docs/perf_counters.md) with PFM support and disabled CPU frequency scaling. You can run the benchmark suite yourself with the `bench` subcommand and optionally some variant feature flag:

```bash
$ cargo bench --features mceliece348864
```

## Is it correct?

Yes, besides passing unittests (derived from the C implementation), the generated KAT KEM test files have equivalent MD5 hashes. Namely …

<table>
  <thead>
    <tr><td>variant</td><td>expected MD5 hash</td></tr>
  </thead><tbody>
    <tr><td>mceliece348864</td><td><code>d2def196fde89e938d3d45b2c6f806aa</code></td></tr>
    <tr><td>mceliece348864f</td><td><code>84b5357d8dd656bed9297e28beb15057</code></td></tr>
    <tr><td>mceliece460896</td><td><code>8aac2122916b901172e49e009efeede6</code></td></tr>
    <tr><td>mceliece460896f</td><td><code>d84d3b179e303b9f3fc32ccb6befb886</code></td></tr>
    <tr><td>mceliece6688128</td><td><code>b86987d56c45da2e326556864e66bda7</code></td></tr>
    <tr><td>mceliece6688128f</td><td><code>ae1e42cac2a885a87a2c241e05391481</code></td></tr>
    <tr><td>mceliece6960119</td><td><code>9d9b3c9e8d7595503248131c584394be</code></td></tr>
    <tr><td>mceliece6960119f</td><td><code>c79b1bd28fd307f8d157bd566374bfb3</code></td></tr>
    <tr><td>mceliece8192128</td><td><code>b233e2585359a1133a1135c66fa48282</code></td></tr>
    <tr><td>mceliece8192128f</td><td><code>d21bcb80dde24826e2c14254da917df3</code></td></tr>
  </tbody>
</table>

## Where is the source code?

On [github](https://github.com/prokls/classic-mceliece-rust).

## What is the content's license?

[MIT License](LICENSE.txt)

## Changelog

* **2022-09-08 version 2.0.1:** fix README documentation
* **2022-09-06 version 2.0.0:** refined API with heap-allocated keys and RustCrypto integration
* **2022-09-06 version 1.1.0:** add CI, clippy, infallible SHAKE impl, forbid unsafe code
* **2022-04-12 version 1.0.1:** fix C&P mistakes in documentation
* **2022-04-01 version 1.0.0:** public release (no April fools though)

## Where can I ask you to fix a bug?

On [github](https://github.com/prokls/classic-mceliece-rust/issues).
