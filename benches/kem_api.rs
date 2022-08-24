use criterion::{black_box, criterion_group, criterion_main, Criterion};
use criterion_cycles_per_byte::CyclesPerByte;

use classic_mceliece_rust::{decapsulate, encapsulate, keypair, CRYPTO_BYTES};
use classic_mceliece_rust::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};

pub fn bench_complete_kem(criterion: &mut Criterion<CyclesPerByte>) {
    let mut rng = rand::thread_rng();
    let mut pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk_buf = [0u8; CRYPTO_SECRETKEYBYTES];
    let mut ss_buf_bob = [0u8; CRYPTO_BYTES];
    let mut ss_buf_alice = [0u8; CRYPTO_BYTES];

    criterion.bench_function("kem", |b| {
        b.iter(|| {
            let (pk, sk) = keypair(&mut pk_buf, &mut sk_buf, &mut rng);
            let (ct, ss_bob) = encapsulate(&pk, &mut ss_buf_bob, &mut rng);
            let ss_alice = decapsulate(&ct, &sk, &mut ss_buf_alice);
            assert_eq!(
                ss_bob.as_array(),
                ss_alice.as_array(),
                "shared keys do not match"
            );
        })
    });
}

pub fn bench_kem_keypair(criterion: &mut Criterion<CyclesPerByte>) {
    let mut rng = rand::thread_rng();
    let mut pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk_buf = [0u8; CRYPTO_SECRETKEYBYTES];

    criterion.bench_function("kem_keypair", |b| {
        b.iter(|| {
            black_box(keypair(&mut pk_buf, &mut sk_buf, &mut rng));
        })
    });
}

pub fn bench_kem_enc(criterion: &mut Criterion<CyclesPerByte>) {
    let mut rng = rand::thread_rng();
    let mut pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk_buf = [0u8; CRYPTO_SECRETKEYBYTES];
    let mut ss_buf = [0u8; CRYPTO_BYTES];

    let (pk, _) = keypair(&mut pk_buf, &mut sk_buf, &mut rng);

    criterion.bench_function("kem_enc", |b| {
        b.iter(|| {
            black_box(encapsulate(&pk, &mut ss_buf, &mut rng));
        })
    });
}

pub fn bench_kem_dec(criterion: &mut Criterion<CyclesPerByte>) {
    let mut rng = rand::thread_rng();
    let mut pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk_buf = [0u8; CRYPTO_SECRETKEYBYTES];
    let mut ss_buf = [0u8; CRYPTO_BYTES];

    let (pk, sk) = keypair(&mut pk_buf, &mut sk_buf, &mut rng);
    let (ct, _) = encapsulate(&pk, &mut ss_buf, &mut rng);

    criterion.bench_function("kem_dec", |b| {
        b.iter(|| {
            black_box(decapsulate(&ct, &sk, &mut ss_buf));
        })
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench_complete_kem, bench_kem_keypair, bench_kem_enc, bench_kem_dec
);
criterion_main!(benches);
