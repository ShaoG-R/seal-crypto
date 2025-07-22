#![cfg(feature = "aes-gcm")]

use criterion::{Criterion, criterion_group};
use seal_crypto::{
    prelude::*,
    schemes::aead::aes_gcm::{Aes128Gcm, Aes256Gcm},
};
use std::hint::black_box;

const KB: usize = 1024;
const SIZES: [usize; 3] = [KB, 16 * KB, 128 * KB];

pub fn bench_aes_gcm(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES-GCM");

    for &size in SIZES.iter() {
        let message = vec![0u8; size];
        let aad = b"authenticated but not encrypted data";
        let nonce_128 = vec![0u8; Aes128Gcm::NONCE_SIZE];
        let nonce_256 = vec![0u8; Aes256Gcm::NONCE_SIZE];

        // --- AES-128-GCM ---
        let key_128 = Aes128Gcm::generate_key().unwrap();
        let ciphertext_128 = Aes128Gcm::encrypt(&key_128, &nonce_128, &message, Some(aad)).unwrap();

        group.bench_function(format!("AES-128-GCM Encrypt ({} bytes)", size), |b| {
            b.iter(|| {
                Aes128Gcm::encrypt(
                    black_box(&key_128),
                    black_box(&nonce_128),
                    black_box(&message),
                    black_box(Some(aad)),
                )
            })
        });

        group.bench_function(format!("AES-128-GCM Decrypt ({} bytes)", size), |b| {
            b.iter(|| {
                Aes128Gcm::decrypt(
                    black_box(&key_128),
                    black_box(&nonce_128),
                    black_box(&ciphertext_128),
                    black_box(Some(aad)),
                )
            })
        });

        // --- AES-256-GCM ---
        let key_256 = Aes256Gcm::generate_key().unwrap();
        let ciphertext_256 = Aes256Gcm::encrypt(&key_256, &nonce_256, &message, Some(aad)).unwrap();

        group.bench_function(format!("AES-256-GCM Encrypt ({} bytes)", size), |b| {
            b.iter(|| {
                Aes256Gcm::encrypt(
                    black_box(&key_256),
                    black_box(&nonce_256),
                    black_box(&message),
                    black_box(Some(aad)),
                )
            })
        });

        group.bench_function(format!("AES-256-GCM Decrypt ({} bytes)", size), |b| {
            b.iter(|| {
                Aes256Gcm::decrypt(
                    black_box(&key_256),
                    black_box(&nonce_256),
                    black_box(&ciphertext_256),
                    black_box(Some(aad)),
                )
            })
        });
    }

    // --- Key Generation ---
    group.bench_function("AES-128-GCM KeyGen", |b| {
        b.iter(|| Aes128Gcm::generate_key())
    });
    group.bench_function("AES-256-GCM KeyGen", |b| {
        b.iter(|| Aes256Gcm::generate_key())
    });

    group.finish();
}

criterion_group!(benches, bench_aes_gcm);
