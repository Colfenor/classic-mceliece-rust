use criterion::{black_box, criterion_group, criterion_main, Criterion};
use criterion_cycles_per_byte::CyclesPerByte;

use classic_mceliece_rust::{decaps, encaps, keypair};
use classic_mceliece_rust::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};

pub fn bench_complete_kem(criterion: &mut Criterion<CyclesPerByte>) {
    let mut rng = rand::thread_rng();
    let mut pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk_buf = [0u8; CRYPTO_SECRETKEYBYTES];

    criterion.bench_function("kem", |b| {
        b.iter(|| {
            let (sk, pk) = keypair(&mut sk_buf, &mut pk_buf, &mut rng);
            let (ct, ss_bob) = encaps(&pk, &mut rng);
            let ss_alice = decaps(&sk, &ct);
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
            black_box(keypair(&mut sk, &mut pk, &mut rng));
        })
    });
}

pub fn bench_kem_enc(criterion: &mut Criterion<CyclesPerByte>) {
    let mut rng = rand::thread_rng();
    let mut pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk_buf = [0u8; CRYPTO_SECRETKEYBYTES];

    let (_, pk) = keypair(&mut sk_buf, &mut pk_buf, &mut rng);

    criterion.bench_function("kem_enc", |b| {
        b.iter(|| {
            black_box(encaps(&pk, &mut rng));
        })
    });
}

pub fn bench_kem_dec(criterion: &mut Criterion<CyclesPerByte>) {
    let mut rng = rand::thread_rng();
    let mut pk_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk_buf = [0u8; CRYPTO_SECRETKEYBYTES];

    let (sk, pk) = keypair(&mut sk_buf, &mut pk_buf, &mut rng);
    let (ct, _) = encaps(&pk, &mut rng);

    criterion.bench_function("kem_dec", |b| {
        b.iter(|| {
            black_box(decaps(&sk, &ct));
        })
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench_complete_kem, bench_kem_keypair, bench_kem_enc, bench_kem_dec
);
criterion_main!(benches);
