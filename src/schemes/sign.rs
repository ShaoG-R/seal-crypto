//! Schemes for digital signatures.
//!
//! 数字签名方案。

#[cfg(feature = "rsa")]
pub use crate::systems::asymmetric::rsa::RsaScheme;

#[cfg(feature = "dilithium")]
pub use crate::systems::asymmetric::dilithium::DilithiumScheme;

/// Parameters for the RSA signature scheme.
///
/// RSA 签名方案的参数。
#[cfg(feature = "rsa")]
pub mod rsa {
    pub use crate::systems::asymmetric::rsa::{Rsa2048, Rsa4096};
    pub use crate::traits::hash::{Sha256, Sha384, Sha512};
}

/// Parameters for the Dilithium signature scheme.
///
/// Dilithium 签名方案的参数。
#[cfg(feature = "dilithium")]
pub mod dilithium {
    pub use crate::systems::asymmetric::dilithium::{Dilithium2, Dilithium3, Dilithium5};
}
