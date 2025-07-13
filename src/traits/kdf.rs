//! Defines traits for key and password derivation functions.
//!
//! 定义了密钥和密码派生函数的 trait。

use crate::errors::Error;
use crate::traits::algorithm::Algorithm;

#[cfg(feature = "secrecy")]
use secrecy::SecretBox;
#[cfg(feature = "std")]
use thiserror::Error;
use zeroize::Zeroizing;

/// A key derived from a KDF, wrapped in `Zeroizing` for security.
///
/// 从 KDF 派生出的密钥，使用 `Zeroizing` 确保安全。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedKey(pub Zeroizing<Vec<u8>>);

impl DerivedKey {
    pub fn new(key_material: Vec<u8>) -> Self {
        Self(Zeroizing::new(key_material))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Defines errors that can occur during key derivation.
///
/// 定义了在密钥派生过程中可能发生的错误。
#[cfg_attr(feature = "std", derive(Error))]
#[derive(Debug, PartialEq, Eq)]
pub enum KdfError {
    /// Derivation failed, often due to an internal cryptographic error.
    ///
    /// 派生失败，通常是由于内部加密错误。
    #[cfg_attr(feature = "std", error("Key derivation failed"))]
    DerivationFailed,

    /// The requested output length is invalid or too large for this KDF.
    ///
    /// 提供的输出长度对于此 KDF 无效或过大。
    #[cfg_attr(feature = "std", error("Invalid output length for this KDF"))]
    InvalidOutputLength,

    /// Salt generation failed.
    ///
    /// 盐生成失败。
    #[cfg_attr(feature = "std", error("Salt generation failed"))]
    SaltGenerationFailed,

    /// The operation is not supported in `no_std` environment.
    ///
    /// 该操作在 `no_std` 环境中不受支持。
    #[cfg_attr(
        feature = "std",
        error("This operation is not supported in `no_std` mode")
    )]
    UnsupportedInNoStd,
}

/// A top-level trait for all derivation algorithms (KDFs, PBKDFs, etc.).
///
/// 所有派生算法（KDF、PBKDF 等）的顶层 trait。
pub trait Derivation: Algorithm + Sync + Send {}

/// A trait for Key Derivation Functions (KDFs) that derive keys from a high-entropy Input Keying Material (IKM).
///
/// 用于从高熵输入密钥材料 (IKM) 派生密钥的密钥派生函数 (KDF) 的 trait。
pub trait KeyBasedDerivation: Derivation {
    /// Derives one or more secure keys from Input Keying Material (IKM).
    ///
    /// # Arguments
    /// * `ikm` - The Input Keying Material. This is the source of entropy, such as a master key or a shared secret from key agreement.
    /// * `salt` - An optional salt. Using a salt is highly recommended to enhance security.
    /// * `info` - Optional context and application-specific information.
    /// * `output_len` - The desired length of the derived key in bytes.
    ///
    /// # Returns
    /// The derived key of `output_len` bytes.
    ///
    /// 从输入密钥材料 (IKM) 派生出一个或多个安全密钥。
    ///
    /// # 参数
    /// * `self` - 方案的实例，可能包含配置。
    /// * `ikm` - 输入密钥材料。这通常是熵的来源，例如主密钥或从密钥协商中获得的共享秘密。
    /// * `salt` - 可选的盐。强烈推荐使用，可以增强安全性。
    /// * `info` - 可选的上下文和应用程序特定信息。
    /// * `output_len` - 期望派生的密钥长度（以字节为单位）。
    ///
    /// # 返回
    /// 派生出的密钥，长度为 `output_len`。
    fn derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<DerivedKey, Error>;
}

/// A trait for Password-Based Key Derivation Functions (PBKDFs) that derive keys from a low-entropy password.
/// These functions are typically computationally intensive to protect against brute-force attacks.
///
/// 用于从低熵密码派生密钥的基于密码的密钥派生函数 (PBKDF) 的 trait。
/// 这些函数通常是计算密集型的，以防止暴力破解攻击。
#[cfg(feature = "secrecy")]
pub trait PasswordBasedDerivation: Derivation {
    /// The recommended length for the salt, in bytes.
    ///
    /// 推荐的盐长度（以字节为单位）。
    const RECOMMENDED_SALT_LENGTH: usize = 16;

    /// Generates a cryptographically secure salt.
    ///
    /// This default implementation uses `getrandom` to generate a salt of `RECOMMENDED_SALT_LENGTH`.
    /// Schemes can override this method if they have specific requirements for salt generation.
    ///
    /// # Returns
    /// A `Vec<u8>` containing the generated salt.
    ///
    /// 生成一个加密安全的盐。
    ///
    /// 此默认实现使用 `getrandom` 来生成长度为 `RECOMMENDED_SALT_LENGTH` 的盐。
    /// 如果方案有特定的盐生成要求，可以重写此方法。
    ///
    /// # 返回
    /// 包含生成的盐的 `Vec<u8>`。
    fn generate_salt(&self) -> Result<Vec<u8>, Error> {
        let mut salt = vec![0u8; Self::RECOMMENDED_SALT_LENGTH];
        getrandom::fill(&mut salt).map_err(|_| Error::Kdf(KdfError::SaltGenerationFailed))?;
        Ok(salt)
    }
    /// Derives a secure key from a password.
    ///
    /// # Arguments
    /// * `self` - The scheme instance, which may contain configuration like the number of iterations.
    /// * `password` - The password to derive the key from.
    /// * `salt` - A salt. It is crucial for security and must be unique per password.
    /// * `output_len` - The desired length of the derived key in bytes.
    ///
    /// # Returns
    /// The derived key of `output_len` bytes.
    ///
    /// 从密码派生一个安全密钥。
    ///
    /// # 参数
    /// * `self` - 方案的实例，可能包含配置，例如迭代次数。
    /// * `password` - 用于派生密钥的密码。
    /// * `salt` - 盐。这对安全性至关重要，每个密码都必须是唯一的。
    /// * `output_len` - 期望派生的密钥长度（以字节为单位）。
    ///
    /// # 返回
    /// 派生出的密钥，长度为 `output_len`。
    fn derive(
        &self,
        password: &SecretBox<[u8]>,
        salt: &[u8],
        output_len: usize,
    ) -> Result<DerivedKey, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_key_wrapper_test() {
        let key_data = vec![1, 2, 3, 4, 5];
        let derived_key = DerivedKey::new(key_data.clone());
        assert_eq!(derived_key.as_bytes(), key_data.as_slice());
    }
}