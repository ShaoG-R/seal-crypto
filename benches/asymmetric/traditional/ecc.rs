use criterion::{criterion_group, Criterion};
use seal_crypto::{
    prelude::*,
    schemes::asymmetric::traditional::ecc::{EcdsaP256, Ed25519},
};
use std::hint::black_box;

fn bench_ecc(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECC");
    let message = b"message to be signed";

    // --- EcdsaP256 ---
    group.bench_function("EcdsaP256 KeyGen", |b| b.iter(EcdsaP256::generate_keypair));

    let (ecdsa_pk, ecdsa_sk) = EcdsaP256::generate_keypair().unwrap();
    let ecdsa_signature = EcdsaP256::sign(&ecdsa_sk, message).unwrap();

    group.bench_function("EcdsaP256 Sign", |b| {
        b.iter(|| EcdsaP256::sign(black_box(&ecdsa_sk), black_box(message)))
    });

    group.bench_function("EcdsaP256 Verify", |b| {
        b.iter(|| {
            EcdsaP256::verify(
                black_box(&ecdsa_pk),
                black_box(message),
                black_box(&ecdsa_signature),
            )
        })
    });

    // --- Ed25519 ---
    group.bench_function("Ed25519 KeyGen", |b| b.iter(Ed25519::generate_keypair));

    let (ed25519_pk, ed25519_sk) = Ed25519::generate_keypair().unwrap();
    let ed25519_signature = Ed25519::sign(&ed25519_sk, message).unwrap();

    group.bench_function("Ed25519 Sign", |b| {
        b.iter(|| Ed25519::sign(black_box(&ed25519_sk), black_box(message)))
    });

    group.bench_function("Ed25519 Verify", |b| {
        b.iter(|| {
            Ed25519::verify(
                black_box(&ed25519_pk),
                black_box(message),
                black_box(&ed25519_signature),
            )
        })
    });

    group.finish();
}

criterion_group!(benches, bench_ecc);
