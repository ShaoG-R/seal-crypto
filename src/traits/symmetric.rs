//! Defines traits for symmetric authenticated encryption.
//!
//! 定义了对称认证加密的 trait。

use crate::traits::Key;
use crate::{errors::Error, traits::key::SymmetricKeySet};
#[cfg(feature = "std")]
use thiserror::Error;
use zeroize::Zeroizing;

/// A key for a symmetric cipher.
///
/// 对称密码的密钥。
#[allow(dead_code)]
pub type SymmetricKey = Zeroizing<Vec<u8>>;

impl Key for SymmetricKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Zeroizing::new(bytes.to_vec()))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
}

/// Authenticated associated data (AAD).
///
/// 认证的关联数据 (AAD)。
pub type AssociatedData<'a> = &'a [u8];

/// Defines the errors that can occur during symmetric encryption and decryption.
///
/// 定义了在对称加密和解密过程中可能发生的错误。
#[derive(Debug)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum SymmetricError {
    /// Failed to encrypt the plaintext.
    ///
    /// 加密明文失败。
    #[cfg_attr(feature = "std", error("Encryption failed"))]
    Encryption,

    /// Failed to decrypt the ciphertext. This commonly occurs if the key is wrong,
    /// the ciphertext or AAD has been tampered with, or the authentication tag is invalid.
    ///
    /// 解密密文失败。如果密钥错误、密文或 AAD 被篡改，或认证标签无效，则通常会发生这种情况。
    #[cfg_attr(feature = "std", error("Decryption failed"))]
    Decryption,

    /// The provided key has an invalid size.
    ///
    /// 提供的密钥大小无效。
    #[cfg_attr(feature = "std", error("Invalid key size"))]
    InvalidKeySize,

    /// The provided nonce has an invalid size.
    ///
    /// 提供的 nonce 大小无效。
    #[cfg_attr(feature = "std", error("Invalid nonce size"))]
    InvalidNonceSize,

    /// The provided ciphertext is malformed or truncated.
    ///
    /// 提供的密文格式错误或被截断。
    #[cfg_attr(feature = "std", error("Invalid ciphertext"))]
    InvalidCiphertext,

    /// The provided output buffer is too small.
    ///
    /// 提供的输出缓冲区太小。
    #[cfg_attr(feature = "std", error("Output buffer is too small"))]
    OutputTooSmall,
}

/// A trait for a symmetric AEAD cipher system.
///
/// 对称 AEAD 密码系统的 trait。
pub trait SymmetricCipher {
    /// The size of the key in bytes.
    ///
    /// 密钥的大小（以字节为单位）。
    const KEY_SIZE: usize;
    /// The size of the nonce in bytes.
    ///
    /// Nonce 的大小（以字节为单位）。
    const NONCE_SIZE: usize;
    /// The size of the authentication tag in bytes.
    ///
    /// 认证标签的大小（以字节为单位）。
    const TAG_SIZE: usize;
}

/// A trait for Authenticated Encryption with Associated Data (AEAD) ciphers.
///
/// 用于带关联数据的认证加密 (AEAD) 密码的 trait。
pub trait SymmetricEncryptor: SymmetricKeySet + SymmetricCipher {
    /// Encrypts a plaintext with a given nonce, producing a ciphertext with tag.
    ///
    /// # Arguments
    /// * `key` - The secret key.
    /// * `nonce` - The nonce for this specific encryption operation. Must be unique for each call with the same key.
    /// * `plaintext` - The data to encrypt.
    /// * `aad` - Optional associated data to authenticate.
    ///
    /// # Returns
    /// The encrypted data concatenated with the authentication tag: `[ciphertext || tag]`.
    ///
    /// 使用给定的 nonce 加密明文，生成带标签的密文。
    ///
    /// # 参数
    /// * `key` - 密钥。
    /// * `nonce` - 本次加密操作的 nonce。对于同一密钥的每次调用都必须是唯一的。
    /// * `plaintext` - 要加密的数据。
    /// * `aad` - 可选的要认证的关联数据。
    ///
    /// # 返回
    /// 加密后的数据与认证标签连接在一起：`[ciphertext || tag]`。
    fn encrypt(
        key: &Self::Key,
        nonce: &[u8],
        plaintext: &[u8],
        aad: Option<AssociatedData>,
    ) -> Result<Vec<u8>, Error> {
        // The required buffer size is plaintext length + tag size.
        // 所需缓冲区大小为明文长度 + 标签大小。
        let mut buffer = vec![0u8; plaintext.len() + Self::TAG_SIZE];
        let bytes_written = Self::encrypt_to_buffer(key, nonce, plaintext, &mut buffer, aad)?;
        buffer.truncate(bytes_written);
        Ok(buffer)
    }

    /// 使用给定的 nonce 加密明文，并将带标签的密文写入提供的缓冲区。
    ///
    /// # 参数
    /// * `key` - 密钥。
    /// * `nonce` - 本次加密操作的 nonce。对于同一密钥的每次调用都必须是唯一的。
    /// * `plaintext` - 要加密的数据。
    /// * `output` - 用于写入加密数据（密文 || 标签）的缓冲区。必须足够大以容纳密文和标签。
    /// * `aad` - 可选的要认证的关联数据。
    ///
    /// # 返回
    /// 如果加密成功，则返回写入 `output` 的字节数。
    fn encrypt_to_buffer(
        key: &Self::Key,
        nonce: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
        aad: Option<AssociatedData>,
    ) -> Result<usize, Error>;
}

/// A trait for AEAD ciphers that can decrypt a ciphertext.
///
/// 用于可解密密文的 AEAD 密码的 trait。
pub trait SymmetricDecryptor: SymmetricKeySet + SymmetricCipher {
    /// Decrypts a ciphertext, producing the original plaintext.
    ///
    /// # Arguments
    /// * `key` - The secret key.
    /// * `nonce` - The nonce that was used to encrypt the data.
    /// * `ciphertext_with_tag` - The encrypted data concatenated with the authentication tag.
    /// * `aad` - Optional associated data that was authenticated.
    ///
    /// # Returns
    /// The original plaintext if decryption and authentication are successful.
    ///
    /// 解密密文，生成原始明文。
    ///
    /// # 参数
    /// * `key` - 密钥。
    /// * `nonce` - 用于加密数据的 nonce。
    /// * `ciphertext_with_tag` - 加密数据与认证标签连接在一起。
    /// * `aad` - 可选的已认证的关联数据。
    ///
    /// # 返回
    /// 如果解密和认证成功，则返回原始明文。
    fn decrypt(
        key: &Self::Key,
        nonce: &[u8],
        ciphertext_with_tag: &[u8],
        aad: Option<AssociatedData>,
    ) -> Result<Vec<u8>, Error> {
        if ciphertext_with_tag.len() < Self::TAG_SIZE {
            return Err(Error::Symmetric(SymmetricError::InvalidCiphertext));
        }
        // The required buffer size is ciphertext length - tag size.
        // 所需缓冲区大小为密文长度 - 标签大小。
        let mut buffer = vec![0u8; ciphertext_with_tag.len() - Self::TAG_SIZE];
        let bytes_written =
            Self::decrypt_to_buffer(key, nonce, ciphertext_with_tag, &mut buffer, aad)?;
        buffer.truncate(bytes_written);
        Ok(buffer)
    }

    /// 解密密文，并将原始明文写入提供的缓冲区。
    ///
    /// # 参数
    /// * `key` - 密钥。
    /// * `nonce` - 用于加密数据的 nonce。
    /// * `ciphertext_with_tag` - 加密数据与认证标签连接在一起。
    /// * `output` - 用于写入解密后明文的缓冲区。必须足够大以容纳明文。
    /// * `aad` - 可选的已认证的关联数据。
    ///
    /// # 返回
    /// 如果解密和认证成功，则返回写入 `output` 的字节数。
    fn decrypt_to_buffer(
        key: &Self::Key,
        nonce: &[u8],
        ciphertext_with_tag: &[u8],
        output: &mut [u8],
        aad: Option<AssociatedData>,
    ) -> Result<usize, Error>;
}

/// A trait for generating symmetric keys.
///
/// 用于生成对称密钥的 trait。
pub trait SymmetricKeyGenerator: SymmetricKeySet {
    /// The size of the key in bytes.
    ///
    /// 密钥的大小（以字节为单位）。
    const KEY_SIZE: usize;
    /// Generates a new symmetric key.
    ///
    /// 生成一个新的对称密钥。
    fn generate_key() -> Result<Self::Key, Error>;
}

/// A unified trait for a complete symmetric AEAD scheme.
///
/// This trait combines key generation, encryption, and decryption capabilities.
///
/// 一个完整的对称 AEAD 方案的统一 trait。
///
/// 该 trait 结合了密钥生成、加密和解密的能力。
pub trait AeadScheme:
    SymmetricKeySet
    + SymmetricKeyGenerator
    + SymmetricEncryptor
    + SymmetricDecryptor
    + SymmetricCipher
    + Send
    + Sync
{
}

impl<T> AeadScheme for T where
    T: SymmetricKeySet
        + SymmetricKeyGenerator
        + SymmetricEncryptor
        + SymmetricDecryptor
        + SymmetricCipher
        + Send
        + Sync
{
}
