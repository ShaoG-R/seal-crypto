//! Asymmetric cryptographic schemes.
//!
//! 非对称加密方案。

/// RSA based schemes.
///
/// 基于 RSA 的方案。
pub mod rsa {
    pub use crate::systems::asymmetric::rsa::{
        Rsa2048, Rsa4096, RsaKeyParams, RsaPrivateKey, RsaPublicKey, RsaScheme,
    };
}

/// Kyber based schemes.
///
/// 基于 Kyber 的方案。
pub mod kyber {
    pub use crate::systems::asymmetric::kyber::{
        Kyber1024, Kyber512, Kyber768, KyberParams, KyberScheme, KyberSecretKey,
    };
}

/// Dilithium based schemes.
///
/// 基于 Dilithium 的方案。
pub mod dilithium {
    pub use crate::systems::asymmetric::dilithium::{
        Dilithium2, Dilithium3, Dilithium5, DilithiumParams, DilithiumScheme, DilithiumSecretKey,
    };
}
