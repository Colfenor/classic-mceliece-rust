use criterion::{criterion_group, criterion_main, Criterion};
use criterion_cycles_per_byte::CyclesPerByte;

use classic_mceliece_rust::mceliece348864::{crypto_kem_dec, crypto_kem_enc, crypto_kem_keypair};
use classic_mceliece_rust::mceliece348864::{
    CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
};

pub fn bench_complete_kem(criterion: &mut Criterion<CyclesPerByte>) {
    let mut rng = rand::thread_rng();
    let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
    let mut ct = [0u8; CRYPTO_CIPHERTEXTBYTES];
    let mut ss_alice = [0u8; CRYPTO_BYTES];
    let mut ss_bob = [0u8; CRYPTO_BYTES];

    criterion.bench_function("kem", |b| {
        b.iter(|| {
            crypto_kem_keypair(&mut pk, &mut sk, &mut rng);
            crypto_kem_enc(&mut ct, &mut ss_alice, &pk, &mut rng);
            crypto_kem_dec(&mut ss_bob, &ct, &sk);
            assert_eq!(ss_bob, ss_alice, "shared keys do not match");
        })
    });
}

pub fn bench_kem_keypair(criterion: &mut Criterion<CyclesPerByte>) {
    let mut rng = rand::thread_rng();
    let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];

    criterion.bench_function("kem_keypair", |b| {
        b.iter(|| {
            crypto_kem_keypair(&mut pk, &mut sk, &mut rng);
        })
    });
}

pub fn bench_kem_enc(criterion: &mut Criterion<CyclesPerByte>) {
    let mut rng = rand::thread_rng();
    let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
    let mut ct = [0u8; CRYPTO_CIPHERTEXTBYTES];
    let mut ss_alice = [0u8; CRYPTO_BYTES];

    crypto_kem_keypair(&mut pk, &mut sk, &mut rng);

    criterion.bench_function("kem_enc", |b| {
        b.iter(|| {
            crypto_kem_enc(&mut ct, &mut ss_alice, &pk, &mut rng);
        })
    });
}

pub fn bench_kem_dec(criterion: &mut Criterion<CyclesPerByte>) {
    let mut rng = rand::thread_rng();
    let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
    let mut ct = [0u8; CRYPTO_CIPHERTEXTBYTES];
    let mut ss_alice = [0u8; CRYPTO_BYTES];
    let mut ss_bob = [0u8; CRYPTO_BYTES];

    crypto_kem_keypair(&mut pk, &mut sk, &mut rng);
    crypto_kem_enc(&mut ct, &mut ss_alice, &pk, &mut rng);

    criterion.bench_function("kem_dec", |b| {
        b.iter(|| {
            crypto_kem_dec(&mut ss_bob, &ct, &sk);
        })
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench_complete_kem, bench_kem_keypair, bench_kem_enc, bench_kem_dec
);
criterion_main!(benches);
