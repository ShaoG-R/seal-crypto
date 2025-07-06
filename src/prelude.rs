//! A "prelude" for users of the `seal-crypto` crate.
//! This prelude is designed to be imported with a glob, i.e., `use seal_crypto::prelude::*;`.
//!
//! `seal-crypto` crate 用户的 "prelude"。
//! 这个 prelude 设计为通过 glob 导入，即 `use seal_crypto::prelude::*;`。
pub use crate::errors::Error as CryptoError;
#[cfg(feature = "secrecy")]
pub use crate::traits::PasswordBasedDerivation;
pub use crate::traits::{
    AeadScheme,
    // core
    Algorithm,
    AsymmetricKeySet,
    // KDF
    Derivation,
    DerivedKey,
    // hash
    KdfError,
    Kem,
    KemError,
    Key,
    KeyAgreement,
    KeyAgreementError,
    KeyBasedDerivation,
    KeyError,
    // asymmetric
    KeyGenerator,
    KeyPair,
    PrivateKey,
    PublicKey,
    Signature,
    SignatureError,
    SignatureScheme,
    Signer,
    SymmetricCipher,
    SymmetricDecryptor,
    SymmetricEncryptor,
    SymmetricError,
    // symmetric
    SymmetricKeyGenerator,
    SymmetricKeySet,
    Verifier,
};
#[cfg(feature = "digest")]
pub use crate::traits::{Hasher, XofDerivation};
#[cfg(feature = "digest")]
pub use ::digest::XofReader as DigestXofReader;
