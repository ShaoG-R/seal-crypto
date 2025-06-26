//! Defines traits for cryptographic keys.
//!
//! 定义了加密密钥的核心 trait。
use crate::errors::Error;
use crate::traits::algorithm::Algorithm;
use zeroize::Zeroize;

/// Defines errors that can occur during key operations.
///
/// 定义了在密钥操作期间可能发生的错误。
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum KeyError {
    /// Failed to generate a key.
    ///
    /// 生成密钥失败。
    #[cfg_attr(feature = "std", error("Key generation failed"))]
    GenerationFailed,
    /// The provided data is not a valid key encoding.
    ///
    /// 提供的密钥编码无效。
    #[cfg_attr(feature = "std", error("Invalid key encoding"))]
    InvalidEncoding,
}

/// A blanket trait for all key types, defining common properties and behaviors.
///
/// 适用于所有密钥类型的通用 trait，定义了通用的属性和行为。
pub trait Key: Sized + Send + Sync + 'static {
    /// Deserializes a key from its byte representation.
    ///
    /// 从字节表示反序列化密钥。
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error>;

    /// Serializes the key into its byte representation.
    ///
    /// 将密钥序列化为字节表示。
    fn to_bytes(&self) -> Vec<u8>;
}

/// A marker trait for public keys.
///
/// 公钥的标记 trait。
pub trait PublicKey: Key + Clone + for<'a> From<&'a Self> {}

/// A marker trait for private keys, generic over its corresponding public key type.
///
/// 私钥的标记 trait，它对其对应的公钥类型是通用的。
pub trait PrivateKey<P: PublicKey>: Key + Zeroize {}

/// Defines the set of keys used in an asymmetric cryptographic scheme.
///
/// 定义非对称加密方案中使用的密钥集。
pub trait AsymmetricKeySet: Algorithm {
    type PublicKey: PublicKey;
    type PrivateKey: PrivateKey<Self::PublicKey>;
}

/// Defines the key used in a symmetric cryptographic scheme.
///
/// 定义对称加密方案中使用的密钥。
pub trait SymmetricKeySet: Algorithm {
    type Key: 'static;
}

/// A trait that associates a private key with its corresponding public key.
///
/// 将私钥与其对应公钥关联的 trait。
pub trait KeyPair<P: PublicKey>: PrivateKey<P> {
    /// Returns a reference to the public key.
    fn public_key(&self) -> P;
}
