use criterion::{criterion_group, Criterion};
use seal_crypto::{
    prelude::*,
    schemes::symmetric::chacha20_poly1305::{ChaCha20Poly1305, XChaCha20Poly1305},
};
use std::hint::black_box;

const KB: usize = 1024;
const SIZES: [usize; 3] = [KB, 16 * KB, 128 * KB];

fn bench_chacha20_poly1305(c: &mut Criterion) {
    let mut group = c.benchmark_group("ChaCha20-Poly1305");

    for &size in SIZES.iter() {
        let message = vec![0u8; size];
        let aad = b"authenticated but not encrypted data";
        let nonce_chacha = vec![0u8; ChaCha20Poly1305::NONCE_SIZE];
        let nonce_xchacha = vec![0u8; XChaCha20Poly1305::NONCE_SIZE];

        // --- ChaCha20-Poly1305 ---
        let key_chacha = ChaCha20Poly1305::generate_key().unwrap();
        let ciphertext_chacha =
            ChaCha20Poly1305::encrypt(&key_chacha, &nonce_chacha, &message, Some(aad)).unwrap();

        group.bench_function(format!("ChaCha20-Poly1305 Encrypt ({} bytes)", size), |b| {
            b.iter(|| {
                ChaCha20Poly1305::encrypt(
                    black_box(&key_chacha),
                    black_box(&nonce_chacha),
                    black_box(&message),
                    black_box(Some(aad)),
                )
            })
        });

        group.bench_function(format!("ChaCha20-Poly1305 Decrypt ({} bytes)", size), |b| {
            b.iter(|| {
                ChaCha20Poly1305::decrypt(
                    black_box(&key_chacha),
                    black_box(&nonce_chacha),
                    black_box(&ciphertext_chacha),
                    black_box(Some(aad)),
                )
            })
        });

        // --- XChaCha20-Poly1305 ---
        let key_xchacha = XChaCha20Poly1305::generate_key().unwrap();
        let ciphertext_xchacha =
            XChaCha20Poly1305::encrypt(&key_xchacha, &nonce_xchacha, &message, Some(aad)).unwrap();

        group.bench_function(
            format!("XChaCha20-Poly1305 Encrypt ({} bytes)", size),
            |b| {
                b.iter(|| {
                    XChaCha20Poly1305::encrypt(
                        black_box(&key_xchacha),
                        black_box(&nonce_xchacha),
                        black_box(&message),
                        black_box(Some(aad)),
                    )
                })
            },
        );

        group.bench_function(
            format!("XChaCha20-Poly1305 Decrypt ({} bytes)", size),
            |b| {
                b.iter(|| {
                    XChaCha20Poly1305::decrypt(
                        black_box(&key_xchacha),
                        black_box(&nonce_xchacha),
                        black_box(&ciphertext_xchacha),
                        black_box(Some(aad)),
                    )
                })
            },
        );
    }

    // --- Key Generation ---
    group.bench_function("ChaCha20-Poly1305 KeyGen", |b| {
        b.iter(|| ChaCha20Poly1305::generate_key())
    });
    group.bench_function("XChaCha20-Poly1305 KeyGen", |b| {
        b.iter(|| XChaCha20Poly1305::generate_key())
    });

    group.finish();
}

criterion_group!(benches, bench_chacha20_poly1305);
