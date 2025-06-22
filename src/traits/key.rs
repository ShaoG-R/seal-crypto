//! Defines the core traits for cryptographic keys.
//!
//! 定义了加密密钥的核心 trait。
use crate::errors::Error;
use zeroize::Zeroize;

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
pub trait AsymmetricKeySet: 'static + Sized {
    type PublicKey: PublicKey;
    type PrivateKey: PrivateKey<Self::PublicKey>;
}

/// Defines the key used in a symmetric cryptographic scheme.
///
/// 定义对称加密方案中使用的密钥。
pub trait SymmetricKeySet: 'static + Sized {
    type Key: 'static;
}

/// A trait that provides a unique name for a cryptographic algorithm.
///
/// 为加密算法提供唯一名称的 trait。
pub trait Algorithm: AsymmetricKeySet {
    /// The unique name of the signature algorithm (e.g., "RSA-PSS-SHA256").
    ///
    /// 签名算法的唯一名称（例如，"RSA-PSS-SHA256"）。
    const NAME: &'static str;
}

/// A trait for schemes that can generate a new cryptographic key pair.
///
/// 用于可生成新加密密钥对的方案的 trait。
pub trait KeyGenerator: Algorithm {
    /// Generates a new key pair (public and private key).
    ///
    /// # Returns
    /// A result containing the key pair, or an error if generation fails.
    ///
    /// 生成一个新的密钥对（公钥和私钥）。
    ///
    /// # 返回
    /// 一个包含密钥对的 `Result`，如果生成失败则返回错误。
    fn generate_keypair() -> Result<(Self::PublicKey, Self::PrivateKey), Error>;
}

/// A trait that associates a private key with its corresponding public key.
///
/// 将私钥与其对应公钥关联的 trait。
pub trait KeyPair<P: PublicKey>: PrivateKey<P> {
    /// Returns a reference to the public key.
    fn public_key(&self) -> P;
}
