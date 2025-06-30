use criterion::{criterion_group, Criterion};
use seal_crypto::{
    prelude::*,
    schemes::asymmetric::traditional::rsa::*,
    schemes::hash::{Sha256, Sha512},
};
use std::hint::black_box;

fn bench_rsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("RSA");
    let message = b"message for PSS signing";

    // --- RSA-2048 with SHA-256 ---
    group.bench_function("Rsa2048<Sha256> KeyGen", |b| {
        b.iter(Rsa2048::<Sha256>::generate_keypair)
    });

    let (pk_2048, sk_2048) = Rsa2048::<Sha256>::generate_keypair().unwrap();

    // KEM
    let (_, encapsulated_key_2048) = Rsa2048::<Sha256>::encapsulate(&pk_2048).unwrap();
    group.bench_function("Rsa2048<Sha256> KEM Encapsulate", |b| {
        b.iter(|| Rsa2048::<Sha256>::encapsulate(black_box(&pk_2048)))
    });
    group.bench_function("Rsa2048<Sha256> KEM Decapsulate", |b| {
        b.iter(|| {
            Rsa2048::<Sha256>::decapsulate(black_box(&sk_2048), black_box(&encapsulated_key_2048))
        })
    });

    // Signature
    let signature_2048 = Rsa2048::<Sha256>::sign(&sk_2048, message).unwrap();
    group.bench_function("Rsa2048<Sha256> PSS Sign", |b| {
        b.iter(|| Rsa2048::<Sha256>::sign(black_box(&sk_2048), black_box(message)))
    });
    group.bench_function("Rsa2048<Sha256> PSS Verify", |b| {
        b.iter(|| {
            Rsa2048::<Sha256>::verify(
                black_box(&pk_2048),
                black_box(message),
                black_box(&signature_2048),
            )
        })
    });

    // --- RSA-4096 with SHA-512 (Fast operations) ---
    let (pk_4096, sk_4096) = Rsa4096::<Sha512>::generate_keypair().unwrap();

    // KEM
    let (_, encapsulated_key_4096) = Rsa4096::<Sha512>::encapsulate(&pk_4096).unwrap();
    group.bench_function("Rsa4096<Sha512> KEM Encapsulate", |b| {
        b.iter(|| Rsa4096::<Sha512>::encapsulate(black_box(&pk_4096)))
    });
    group.bench_function("Rsa4096<Sha512> KEM Decapsulate", |b| {
        b.iter(|| {
            Rsa4096::<Sha512>::decapsulate(black_box(&sk_4096), black_box(&encapsulated_key_4096))
        })
    });

    // Signature
    let signature_4096 = Rsa4096::<Sha512>::sign(&sk_4096, message).unwrap();
    group.bench_function("Rsa4096<Sha512> PSS Sign", |b| {
        b.iter(|| Rsa4096::<Sha512>::sign(black_box(&sk_4096), black_box(message)))
    });
    group.bench_function("Rsa4096<Sha512> PSS Verify", |b| {
        b.iter(|| {
            Rsa4096::<Sha512>::verify(
                black_box(&pk_4096),
                black_box(message),
                black_box(&signature_4096),
            )
        })
    });

    group.finish();

    // --- RSA-4096 with SHA-512 (Slow KeyGen) ---
    let mut slow_group = c.benchmark_group("RSA-KeyGen-Slow");
    slow_group.sample_size(10);
    slow_group.bench_function("Rsa4096<Sha512> KeyGen", |b| {
        b.iter(Rsa4096::<Sha512>::generate_keypair)
    });
    slow_group.finish();
}

criterion_group!(benches, bench_rsa);
