#![cfg(feature = "argon2")]

use criterion::{Criterion, criterion_group};
use seal_crypto::{prelude::*, schemes::kdf::argon2::Argon2Scheme};
use secrecy::SecretBox;
use std::hint::black_box;

// Use low-cost parameters for benchmarks to ensure they run quickly.
// In a real application, use secure defaults or tuned parameters.
const BENCH_M_COST: u32 = 4096; // 4 MiB
const BENCH_T_COST: u32 = 1;
const BENCH_P_COST: u32 = 1;

pub fn bench_argon2(c: &mut Criterion) {
    let mut group = c.benchmark_group("KDF-Argon2");

    let password = SecretBox::new(Box::from(b"password-for-benchmarking".as_slice()));
    let salt = b"salt-for-benchmarking";
    let output_len = 32;

    let scheme = Argon2Scheme::new(BENCH_M_COST, BENCH_T_COST, BENCH_P_COST);
    let bench_name = format!(
        "Argon2id (m={}, t={}, p={})",
        BENCH_M_COST, BENCH_T_COST, BENCH_P_COST
    );

    group.bench_function(&bench_name, |b| {
        b.iter(|| scheme.derive(black_box(&password), black_box(salt), black_box(output_len)))
    });

    group.finish();
}

criterion_group!(benches, bench_argon2);
