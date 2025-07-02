use criterion::{criterion_group, Criterion};
use seal_crypto::{
    prelude::*,
    schemes::kdf::shake::{Shake128, Shake256},
};
use std::hint::black_box;

fn bench_shake(c: &mut Criterion) {
    let mut group = c.benchmark_group("KDF-SHAKE");

    let ikm = b"shake-benchmark-ikm";
    let salt = b"shake-benchmark-salt";
    let info = b"shake-benchmark-info";
    let output_len = 64;

    // --- SHAKE-128 ---
    let scheme_shake128 = Shake128::default();
    group.bench_function("SHAKE-128", |b| {
        b.iter(|| {
            black_box(scheme_shake128.derive(
                black_box(ikm),
                black_box(Some(salt)),
                black_box(Some(info)),
                black_box(output_len),
            ))
        })
    });

    // --- SHAKE-256 ---
    let scheme_shake256 = Shake256::default();
    group.bench_function("SHAKE-256", |b| {
        b.iter(|| {
            black_box(scheme_shake256.derive(
                black_box(ikm),
                black_box(Some(salt)),
                black_box(Some(info)),
                black_box(output_len),
            ))
        })
    });

    group.finish();
}

criterion_group!(benches, bench_shake); 