# classic-mceliece-rust

A safe pure-rust implementation of the Classic McEliece post-quantum scheme.

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

## How does one use it?

Add this to your `Cargo.toml`:
```toml
[dependencies]
classic-mceliece-rust = "1.0"
```

To use a specific Classic McEliece variant, you need to import it with the corresponding feature flag:

```toml
[dependencies]
classic-mceliece-rust = { version = "1.0", features = ["mceliece6960119"] }
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
    <tr><td>mceliece348864</td><td>439,132,283</td><td>418,968,068</td><td>268,722</td><td>43,444,716</td></tr>
    <tr><td>mceliece348864f</td><td>265,775,807</td><td>222,549,540</td><td>269,555</td><td>43,245,009</td></tr>
    <tr><td>mceliece460896</td><td>1,231,610,738</td><td>1,211,071,786</td><td>461,924</td><td>107,828,642</td></tr>
    <tr><td>mceliece460896f</td><td>723,224,611</td><td>650,813,812</td><td>435,803</td><td>104,153,026</td></tr>
    <tr><td>mceliece6688128</td><td>2,559,092,096</td><td>2,231,201,954</td><td>947,605</td><td>198,260,095</td></tr>
    <tr><td>mceliece6688128f</td><td>1,166,028,776</td><td>1,210,393,799</td><td>1,210,453</td><td>200,919,923</td></tr>
    <tr><td>mceliece6960119</td><td>2,684,515,149</td><td>2,194,168,253</td><td>3,135,087</td><td>194,131,917</td></tr>
    <tr><td>mceliece6960119f</td><td>1,146,146,983</td><td>1,038,560,469</td><td>3,101,435</td><td>194,415,995</td></tr>
    <tr><td>mceliece8192128</td><td>3,044,572,096</td><td>2,873,255,542</td><td>1,068,166</td><td>249,912,972</td></tr>
    <tr><td>mceliece8192128f</td><td>1,362,327,626</td><td>2,009,006,653</td><td>1,790,924</td><td>272,566,816</td></tr>
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

* **2022-04-01 version 1.0.0:** public release (no April fools though)

## Where can I ask you to fix a bug?

On [github](https://github.com/prokls/classic-mceliece-rust/issues).
