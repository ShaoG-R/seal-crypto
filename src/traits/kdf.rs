//! Defines traits for Key Derivation Functions (KDFs).
//!
//! 定义了密钥派生函数 (KDF) 的 trait。

use crate::errors::Error;
use crate::traits::algorithm::Algorithm;
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
}

/// The core trait for a Key Derivation Function (KDF).
///
/// 密钥派生函数 (KDF) 的核心 trait。
pub trait KeyDerivation: Algorithm {
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