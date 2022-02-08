# classic-mceliece-rust

A safe pure-rust implementation of the Classic McEliece post-quantum scheme.

* Classic McEliece is a lattice-based key encapsulation mechanism (KEM)
* The implementation is based on the Classic McEliece reference implementation of [NIST round 3](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions)
* The implementation does not utilize any concurrency techniques (SIMD/threading/…, except maybe auto-vectorization on your CPU)
* It depends on `sha3` as SHA-3 implementation and `aes` as AES block cipher (used as RNG) implementation
* TODO It passes the 100 testcases of the C reference implementation
* It implements all 10 variants of the Classic McEliece KEM
* TODO The implementation takes between 200 milliseconds (`mceliece348864`) and 300 milliseconds (`mceliece8192128f`) to run on a modern computer
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

## How does one use it?

Add this to your `Cargo.toml`:
```toml
[dependencies]
classic-mceliece-rust = "0.9"
```

TODO To use a specific Classic McEliece variant, you need to import it with the corresponding feature flag:

```toml
[dependencies]
classic-mceliece-rust = { version = "0.9", features = ["mceliece6960119"] }
```

The `simple` example illustrates the API:
```rust
use classic_mceliece_rust::AesState;
use classic_mceliece_rust::{crypto_kem_dec, crypto_kem_enc, crypto_kem_keypair};
use classic_mceliece_rust::{CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};

fn main() -> Result<(), Box<dyn error::Error>> {
  let mut rng = AesState::new();
  let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
  let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
  let mut ct = [0u8; CRYPTO_CIPHERTEXTBYTES];
  let mut ss_alice = [0u8; CRYPTO_BYTES];
  let mut ss_bob = [0u8; CRYPTO_BYTES];

  crypto_kem_keypair(&mut pk, &mut sk, &mut rng)?;
  crypto_kem_enc(&mut ct, &mut ss_bob, &pk, &mut rng)?;
  crypto_kem_dec(&mut ss_alice, &ct, &sk)?;

  assert_eq!(ss_bob, ss_alice);
}
```

## How does one run it?

This library comes with two examples:

```bash
$ cargo run --example simple
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
    <tr><td>mceliece348864</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece348864f</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece460896</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece460896f</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece6688128</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece6688128f</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece6960119</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece6960119f</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece8192128</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece8192128f</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
  </tbody>
</table>

The C reference implementation yielded the following runtime results:

<table>
  <thead>
    <tr><td></td><td>complete KEM</td><td>keypair</td><td>enc</td><td>dec</td></tr>
  </thead><tbody>
    <tr><td>mceliece348864</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece348864f</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece460896</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece460896f</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece6688128</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece6688128f</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece6960119</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece6960119f</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece8192128</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
    <tr><td>mceliece8192128f</td><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
  </tbody>
</table>

The tests were done on a Lenovo Thinkpad x260 (Intel Core i5-6200U CPU @ 2.30GHz). In the case of rust, [criterion 0.3.5](https://crates.io/crates/criterion) has been used as given in `benches/` and in case of C, Google's [benchmark](https://github.com/google/benchmark/blob/v1.6.1/docs/perf_counters.md) with PFM support and disabled CPU frequency scaling. You can run the benchmark suite yourself with the `bench` subcommand and optionally some variant feature flag:

```bash
$ cargo bench --features mceliece348864
```

## Where is the source code?

On [github](https://github.com/prokls/classic-mceliece-rust).

## What is the content's license?

[MIT License](LICENSE.txt)

## Changelog

* **2022-02-11 version 0.9.0:** public release

## Where can I ask you to fix a bug?

On [github](https://github.com/prokls/classic-mceliece-rust/issues).
