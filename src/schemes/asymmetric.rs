//! Asymmetric cryptographic schemes.
//!
//! 非对称加密方案。

/// Traditional asymmetric cryptographic schemes.
///
/// 传统非对称加密方案。
pub mod traditional {
    /// RSA based schemes.
    ///
    /// 基于 RSA 的方案。
    pub mod rsa {
        #[cfg(feature = "rsa")]
        pub use crate::systems::asymmetric::rsa::{
            Rsa2048, Rsa4096, RsaKeyParams, RsaPrivateKey, RsaPublicKey, RsaScheme,
        };
    }
}

/// Post-quantum cryptography schemes
///
/// 后量子密码学方案
pub mod pq {
    /// Kyber KEM, a post-quantum key encapsulation method.
    ///
    /// Kyber KEM，一种后量子密钥封装方法。
    #[cfg(feature = "kyber")]
    pub mod kyber {
        pub use crate::systems::asymmetric::kyber::{
            Kyber1024, Kyber512, Kyber768, KyberParams, KyberScheme, KyberSecretKey,
        };
    }

    /// Dilithium, a post-quantum signature scheme.
    ///
    /// Dilithium，一种后量子签名方案。
    #[cfg(feature = "dilithium")]
    pub mod dilithium {
        pub use crate::systems::asymmetric::dilithium::{
            Dilithium2, Dilithium3, Dilithium5, DilithiumParams, DilithiumScheme, DilithiumSecretKey,
        };
    }
}
