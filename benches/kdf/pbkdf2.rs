#![cfg(feature = "pbkdf2")]

use criterion::{Criterion, criterion_group};
use seal_crypto::{
    prelude::*,
    schemes::kdf::pbkdf2::{Pbkdf2Sha256, Pbkdf2Sha512},
};
use secrecy::SecretBox;
use std::hint::black_box;

// Use a low iteration count for benchmarks to ensure they run quickly.
// In a real application, use a much higher value (e.g., 600,000 or more).
const BENCH_ITERATIONS: u32 = 1000;

pub fn bench_pbkdf2(c: &mut Criterion) {
    let mut group = c.benchmark_group("KDF-PBKDF2");

    let password = SecretBox::new(Box::from(b"password-for-benchmarking".as_slice()));
    let salt = b"salt-for-benchmarking";
    let output_len = 32;

    // --- PBKDF2-SHA256 ---
    let scheme_sha256 = Pbkdf2Sha256::new(BENCH_ITERATIONS);
    group.bench_function(
        format!("PBKDF2-SHA256 ({} iterations)", BENCH_ITERATIONS),
        |b| {
            b.iter(|| {
                scheme_sha256.derive(black_box(&password), black_box(salt), black_box(output_len))
            })
        },
    );

    // --- PBKDF2-SHA512 ---
    let scheme_sha512 = Pbkdf2Sha512::new(BENCH_ITERATIONS);
    group.bench_function(
        format!("PBKDF2-SHA512 ({} iterations)", BENCH_ITERATIONS),
        |b| {
            b.iter(|| {
                scheme_sha512.derive(black_box(&password), black_box(salt), black_box(output_len))
            })
        },
    );

    group.finish();
}

criterion_group!(benches, bench_pbkdf2);
