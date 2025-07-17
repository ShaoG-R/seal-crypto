//! Defines traits for asymmetric cryptographic operations.
//!
//! 定义了非对称加密操作的 trait。

use crate::errors::Error;
use crate::traits::Key;
use crate::traits::key::AsymmetricKeySet;
#[cfg(feature = "std")]
use thiserror::Error;
use zeroize::Zeroizing;

// --- Key Generator ---
/// A trait for schemes that can generate a new cryptographic key pair.
///
/// 用于可生成新加密密钥对的方案的 trait。
pub trait KeyGenerator: AsymmetricKeySet {
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

// --- Signer / Verifier ---
/// Represents a digital signature, wrapping a byte vector for type safety.
///
/// 代表一个数字签名，为增强类型安全而包装了一个字节向量。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub Vec<u8>);

impl Signature {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Defines the errors that can occur during signing and verification.
///
/// 定义了在签名和验证过程中可能发生的错误。
#[cfg_attr(feature = "std", derive(Error))]
#[derive(Debug, PartialEq, Eq)]
pub enum SignatureError {
    /// Failed to create a digital signature.
    ///
    /// 创建数字签名失败。
    #[cfg_attr(feature = "std", error("Signing failed"))]
    Signing,

    /// Signature verification failed, indicating that the signature is invalid,
    /// the data has been tampered with, or the wrong key was used.
    ///
    /// 签名验证失败，表明签名无效、数据被篡改或使用了错误的密钥。
    #[cfg_attr(feature = "std", error("Verification failed"))]
    Verification,

    /// The provided signature is malformed or has an invalid length.
    ///
    /// 提供的签名格式错误或长度无效。
    #[cfg_attr(feature = "std", error("Invalid signature format"))]
    InvalidSignature,
}

/// A trait for cryptographic schemes that can create digital signatures.
///
/// 用于能够创建数字签名的加密方案的 trait。
pub trait Signer: AsymmetricKeySet {
    /// Creates a digital signature for a given message digest.
    ///
    /// 为给定的消息摘要创建一个数字签名。
    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Signature, Error>;
}

/// A trait for cryptographic schemes that can verify digital signatures.
///
/// 用于能够验证数字签名的加密方案的 trait。
pub trait Verifier: AsymmetricKeySet {
    /// Verifies a digital signature for a given message digest.
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid, otherwise an `Err`.
    ///
    /// 验证给定消息摘要的数字签名。
    ///
    /// # 返回
    /// 如果签名有效，则返回 `Ok(())`，否则返回 `Err`。
    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), Error>;
}

/// A unified trait for a complete signature scheme.
///
/// It combines key generation, signing, and verification capabilities.
/// This is the primary trait that should be implemented by a signature algorithm.
///
/// 一个完整的签名方案的统一 trait。
///
/// 它结合了密钥生成、签名和验证的能力。
/// 这是签名算法应该实现的主要 trait。
pub trait SignatureScheme: KeyGenerator + Signer + Verifier {}

impl<T: KeyGenerator + Signer + Verifier> SignatureScheme for T {}

// --- KEM ---
/// A secret value, derived from a KEM, suitable for use as a symmetric key.
/// It is wrapped in `Zeroizing` to ensure it's wiped from memory when dropped.
///
/// 一个从 KEM 派生的秘密值，适合用作对称密钥。
/// 它被包装在 `Zeroizing` 中，以确保在被丢弃时从内存中清除。
#[allow(dead_code)]
pub type SharedSecret = Zeroizing<Vec<u8>>;

/// The encapsulated key (ciphertext) produced by a KEM.
///
/// KEM 生成的封装密钥（密文）。
#[allow(dead_code)]
pub type EncapsulatedKey = Vec<u8>;

impl Key for EncapsulatedKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(bytes.to_vec())
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
}

/// Defines the errors that can occur during KEM operations.
///
/// 定义 KEM 操作期间可能发生的错误。
#[cfg_attr(feature = "std", derive(Error))]
#[derive(Debug, PartialEq, Eq)]
pub enum KemError {
    /// Failed to encapsulate a shared secret.
    ///
    /// 封装共享密钥失败。
    #[cfg_attr(feature = "std", error("Key encapsulation failed"))]
    Encapsulation,

    /// Failed to decapsulate a shared secret, often due to an invalid
    /// or tampered encapsulated key.
    ///
    /// 解封装共享密钥失败，通常是由于无效或被篡改的封装密钥。
    #[cfg_attr(feature = "std", error("Key decapsulation failed"))]
    Decapsulation,

    /// The provided public key is invalid for the operation.
    ///
    /// 提供的公钥对于该操作无效。
    #[cfg_attr(feature = "std", error("Invalid public key"))]
    InvalidPublicKey,

    /// The provided private key is invalid for the operation.
    ///
    /// 提供的私钥对于该操作无效。
    #[cfg_attr(feature = "std", error("Invalid private key"))]
    InvalidPrivateKey,

    /// The provided encapsulated key (ciphertext) is invalid.
    ///
    /// 提供的封装密钥（密文）无效。
    #[cfg_attr(feature = "std", error("Invalid encapsulated key"))]
    InvalidEncapsulatedKey,
}

/// A trait for a Key Encapsulation Mechanism (KEM).
///
/// KEMs are a class of public-key cryptosystems designed for securely
/// establishing shared secrets.
///
/// 密钥封装机制 (KEM) 的 trait。
///
/// KEM 是一类用于安全建立共享密钥的公钥密码系统。
pub trait Kem: AsymmetricKeySet {
    type EncapsulatedKey: Key;

    /// Generates and encapsulates a shared secret using the recipient's public key.
    ///
    /// # Returns
    /// A tuple containing the `(SharedSecret, EncapsulatedKey)`.
    /// The `SharedSecret` is for the sender to use, and the `EncapsulatedKey`
    /// is to be sent to the recipient.
    ///
    /// 使用接收者的公钥生成并封装一个共享密钥。
    ///
    /// # 返回
    /// 一个包含 `(SharedSecret, EncapsulatedKey)` 的元组。
    /// `SharedSecret` 供发送方使用，`EncapsulatedKey` 用于发送给接收方。
    fn encapsulate(
        public_key: &Self::PublicKey,
    ) -> Result<(SharedSecret, Self::EncapsulatedKey), Error>;

    /// Decapsulates an encapsulated key using the recipient's private key to
    /// recover the shared secret.
    ///
    /// # Returns
    /// The `SharedSecret` that matches the one generated by the sender.
    ///
    /// 使用接收者的私钥解封装一个封装密钥，以恢复共享密钥。
    ///
    /// # 返回
    /// 与发送方生成的 `SharedSecret` 相匹配的共享密钥。
    fn decapsulate(
        private_key: &Self::PrivateKey,
        encapsulated_key: &Self::EncapsulatedKey,
    ) -> Result<SharedSecret, Error>;
}

// --- Key Agreement ---

/// Defines the errors that can occur during key agreement.
///
/// 定义密钥协商期间可能发生的错误。
#[cfg_attr(feature = "std", derive(Error))]
#[derive(Debug, PartialEq, Eq)]
pub enum KeyAgreementError {
    /// Failed to derive the shared secret.
    ///
    /// 派生共享密钥失败。
    #[cfg_attr(feature = "std", error("Key agreement failed"))]
    AgreementFailed,

    /// The peer's public key is invalid for this operation.
    ///
    /// 对方的公钥对于此操作无效。
    #[cfg_attr(feature = "std", error("Invalid peer public key"))]
    InvalidPeerPublicKey,
}

/// A trait for a Key Agreement scheme.
///
/// Key Agreement 方案的 trait。
pub trait KeyAgreement: AsymmetricKeySet {
    /// Derives a shared secret from one's own private key and a peer's public key.
    ///
    /// # Returns
    /// The derived `SharedSecret`.
    ///
    /// 从自己的私钥和对方的公钥派生一个共享密钥。
    ///
    /// # 返回
    /// 派生出的 `SharedSecret`。
    fn agree(
        private_key: &Self::PrivateKey,
        public_key: &Self::PublicKey,
    ) -> Result<SharedSecret, Error>;
}
