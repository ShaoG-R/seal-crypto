//! Schemes for Key Encapsulation Mechanisms (KEMs).
//!
//! 密钥封装机制 (KEM) 方案。

#[cfg(feature = "rsa")]
pub use crate::systems::asymmetric::rsa::RsaScheme;

#[cfg(feature = "kyber")]
pub use crate::systems::asymmetric::kyber::KyberScheme;

/// Parameters for the RSA-KEM scheme.
///
/// RSA-KEM 方案的参数。
#[cfg(feature = "rsa")]
pub mod rsa {
    pub use crate::systems::asymmetric::rsa::{Rsa, Rsa2048, Rsa4096};
    pub use crate::traits::hash::{Sha256, Sha384, Sha512};
}

/// Parameters for the Kyber KEM scheme.
///
/// Kyber KEM 方案的参数。
#[cfg(feature = "kyber")]
pub mod kyber {
    pub use crate::systems::asymmetric::kyber::{Kyber1024, Kyber512, Kyber768};
} 