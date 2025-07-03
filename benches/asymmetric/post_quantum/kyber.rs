#![cfg(feature = "kyber")]

use criterion::{criterion_group, Criterion};
use seal_crypto::{
    prelude::*,
    schemes::asymmetric::post_quantum::kyber::{Kyber1024, Kyber512, Kyber768},
};
use std::hint::black_box;

pub fn bench_kyber(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber");

    // --- Kyber512 ---
    group.bench_function("Kyber512 KeyGen", |b| b.iter(Kyber512::generate_keypair));

    let (pk512, sk512) = Kyber512::generate_keypair().unwrap();
    let (_ss512, encapsulated_key512) = Kyber512::encapsulate(&pk512).unwrap();

    group.bench_function("Kyber512 KEM Encapsulate", |b| {
        b.iter(|| Kyber512::encapsulate(black_box(&pk512)))
    });

    group.bench_function("Kyber512 KEM Decapsulate", |b| {
        b.iter(|| Kyber512::decapsulate(black_box(&sk512), black_box(&encapsulated_key512)))
    });

    // --- Kyber768 ---
    group.bench_function("Kyber768 KeyGen", |b| b.iter(Kyber768::generate_keypair));

    let (pk768, sk768) = Kyber768::generate_keypair().unwrap();
    let (_ss768, encapsulated_key768) = Kyber768::encapsulate(&pk768).unwrap();

    group.bench_function("Kyber768 KEM Encapsulate", |b| {
        b.iter(|| Kyber768::encapsulate(black_box(&pk768)))
    });

    group.bench_function("Kyber768 KEM Decapsulate", |b| {
        b.iter(|| Kyber768::decapsulate(black_box(&sk768), black_box(&encapsulated_key768)))
    });

    // --- Kyber1024 ---
    group.bench_function("Kyber1024 KeyGen", |b| b.iter(Kyber1024::generate_keypair));

    let (pk1024, sk1024) = Kyber1024::generate_keypair().unwrap();
    let (_ss1024, encapsulated_key1024) = Kyber1024::encapsulate(&pk1024).unwrap();

    group.bench_function("Kyber1024 KEM Encapsulate", |b| {
        b.iter(|| Kyber1024::encapsulate(black_box(&pk1024)))
    });

    group.bench_function("Kyber1024 KEM Decapsulate", |b| {
        b.iter(|| Kyber1024::decapsulate(black_box(&sk1024), black_box(&encapsulated_key1024)))
    });

    group.finish();
}

criterion_group!(benches, bench_kyber);
