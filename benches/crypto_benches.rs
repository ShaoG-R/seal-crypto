mod asymmetric;
mod kdf;
mod symmetric;
mod xof;

use criterion::{Criterion, criterion_group, criterion_main};

fn all_benches(c: &mut Criterion) {
    #[cfg(feature = "aes-gcm")]
    symmetric::aes_gcm::bench_aes_gcm(c);
    #[cfg(feature = "chacha20-poly1305")]
    symmetric::chacha20_poly1305::bench_chacha20_poly1305(c);
    #[cfg(feature = "ecc")]
    asymmetric::traditional::ecc::bench_ecc(c);
    #[cfg(feature = "ecdh")]
    asymmetric::traditional::ecdh::bench_ecdh(c);
    #[cfg(feature = "rsa")]
    asymmetric::traditional::rsa::bench_rsa(c);
    #[cfg(feature = "dilithium")]
    asymmetric::post_quantum::dilithium::bench_dilithium(c);
    #[cfg(feature = "kyber")]
    asymmetric::post_quantum::kyber::bench_kyber(c);
    #[cfg(feature = "hkdf")]
    kdf::hkdf::bench_hkdf(c);
    #[cfg(feature = "pbkdf2")]
    kdf::pbkdf2::bench_pbkdf2(c);
    #[cfg(feature = "argon2")]
    kdf::argon2::bench_argon2(c);
    #[cfg(feature = "shake")]
    xof::shake::bench_shake(c);
}

criterion_group!(benches, all_benches);
criterion_main!(benches);
