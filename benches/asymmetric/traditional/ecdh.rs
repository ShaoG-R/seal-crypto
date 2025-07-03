#![cfg(feature = "ecdh")]

use criterion::{criterion_group, Criterion};
use seal_crypto::{prelude::*, schemes::asymmetric::traditional::ecdh::*};
use std::hint::black_box;

pub fn bench_ecdh(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH");

    // --- EcdhP256 ---
    group.bench_function("EcdhP256 KeyGen", |b| b.iter(EcdhP256::generate_keypair));

    let (_alice_pk, alice_sk) = EcdhP256::generate_keypair().unwrap();
    let (bob_pk, _bob_sk) = EcdhP256::generate_keypair().unwrap();

    group.bench_function("EcdhP256 KeyAgreement", |b| {
        b.iter(|| EcdhP256::agree(black_box(&alice_sk), black_box(&bob_pk)))
    });

    group.finish();
}

criterion_group!(benches, bench_ecdh);
