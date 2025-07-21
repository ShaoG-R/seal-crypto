//! A "prelude" for users of the `seal-crypto` crate.
//! This prelude is designed to be imported with a glob, i.e., `use seal_crypto::prelude::*;`.
//!
//! `seal-crypto` crate 用户的 "prelude"。
//! 这个 prelude 设计为通过 glob 导入，即 `use seal_crypto::prelude::*;`。
pub use crate::errors::Error as CryptoError;
#[cfg(all(feature = "secrecy", feature = "getrandom"))]
pub use crate::traits::kdf::PasswordBasedDerivation;
pub use crate::traits::{
    // core
    algorithm::*,
    // KDF
    kdf::*,
    // XOF
    xof::*,
    // key
    key::*,
    // asymmetric
    asymmetric::*,
    // symmetric
    symmetric::*,
    // params
    params::*,
};

#[cfg(feature = "digest")]
pub use digest::XofReader as DigestXofReader;
