//! A "prelude" for users of the `seal-crypto` crate.
//! This prelude is designed to be imported with a glob, i.e., `use seal_crypto::prelude::*;`.
//!
//! `seal-crypto` crate 用户的 "prelude"。
//! 这个 prelude 设计为通过 glob 导入，即 `use seal_crypto::prelude::*;`。
pub use crate::errors::Error as CryptoError;
pub use crate::traits::{
    AeadScheme,
    // core
    Algorithm,
    AsymmetricKeySet,
    // hash
    Hasher,
    Kem,
    Key,
    // asymmetric
    KeyGenerator,
    KeyPair,
    PrivateKey,
    PublicKey,
    SignatureScheme,
    Signer,
    SymmetricCipher,
    SymmetricDecryptor,
    SymmetricEncryptor,
    // symmetric
    SymmetricKeyGenerator,
    SymmetricKeySet,
    Verifier,
};
pub use ::zeroize;
