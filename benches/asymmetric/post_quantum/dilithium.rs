#![cfg(feature = "dilithium")]

use criterion::{Criterion, criterion_group};
use seal_crypto::{
    prelude::*,
    schemes::asymmetric::post_quantum::dilithium::{Dilithium2, Dilithium3, Dilithium5},
};
use std::hint::black_box;

pub fn bench_dilithium(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dilithium");
    let message = b"message to be signed by Dilithium";

    // --- Dilithium2 ---
    group.bench_function("Dilithium2 KeyGen", |b| {
        b.iter(Dilithium2::generate_keypair)
    });

    let (pk2, sk2) = Dilithium2::generate_keypair().unwrap();
    let sig2 = Dilithium2::sign(&sk2, message).unwrap();

    group.bench_function("Dilithium2 Sign", |b| {
        b.iter(|| Dilithium2::sign(black_box(&sk2), black_box(message)))
    });

    group.bench_function("Dilithium2 Verify", |b| {
        b.iter(|| Dilithium2::verify(black_box(&pk2), black_box(message), black_box(&sig2)))
    });

    // --- Dilithium3 ---
    group.bench_function("Dilithium3 KeyGen", |b| {
        b.iter(Dilithium3::generate_keypair)
    });

    let (pk3, sk3) = Dilithium3::generate_keypair().unwrap();
    let sig3 = Dilithium3::sign(&sk3, message).unwrap();

    group.bench_function("Dilithium3 Sign", |b| {
        b.iter(|| Dilithium3::sign(black_box(&sk3), black_box(message)))
    });

    group.bench_function("Dilithium3 Verify", |b| {
        b.iter(|| Dilithium3::verify(black_box(&pk3), black_box(message), black_box(&sig3)))
    });

    // --- Dilithium5 ---
    group.bench_function("Dilithium5 KeyGen", |b| {
        b.iter(Dilithium5::generate_keypair)
    });

    let (pk5, sk5) = Dilithium5::generate_keypair().unwrap();
    let sig5 = Dilithium5::sign(&sk5, message).unwrap();

    group.bench_function("Dilithium5 Sign", |b| {
        b.iter(|| Dilithium5::sign(black_box(&sk5), black_box(message)))
    });

    group.bench_function("Dilithium5 Verify", |b| {
        b.iter(|| Dilithium5::verify(black_box(&pk5), black_box(message), black_box(&sig5)))
    });

    group.finish();
}

criterion_group!(benches, bench_dilithium);
