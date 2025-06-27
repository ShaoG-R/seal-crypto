mod asymmetric;
mod symmetric;

use criterion::criterion_main;

criterion_main! {
    symmetric::aes_gcm::benches,
    symmetric::chacha20_poly1305::benches,
    asymmetric::traditional::ecc::benches,
    asymmetric::traditional::ecdh::benches,
    asymmetric::traditional::rsa::benches,
    asymmetric::post_quantum::dilithium::benches,
    asymmetric::post_quantum::kyber::benches,
}
