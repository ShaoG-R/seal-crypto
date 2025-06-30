use criterion::{criterion_group, Criterion};
use seal_crypto::{
    prelude::*,
    schemes::kdf::hkdf::{HkdfSha256, HkdfSha512},
};
use std::hint::black_box;

fn bench_hkdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("KDF-HKDF");

    let ikm = b"initial-keying-material";
    let salt = b"test-salt";
    let info = b"test-info";
    let output_len = 32;

    // --- HKDF-SHA256 ---
    let scheme_sha256 = HkdfSha256::default();
    group.bench_function("HKDF-SHA256", |b| {
        b.iter(|| {
            scheme_sha256.derive(
                black_box(ikm),
                black_box(Some(salt)),
                black_box(Some(info)),
                black_box(output_len),
            )
        })
    });

    // --- HKDF-SHA512 ---
    let scheme_sha512 = HkdfSha512::default();
    group.bench_function("HKDF-SHA512", |b| {
        b.iter(|| {
            scheme_sha512.derive(
                black_box(ikm),
                black_box(Some(salt)),
                black_box(Some(info)),
                black_box(output_len),
            )
        })
    });

    group.finish();
}

criterion_group!(benches, bench_hkdf); 