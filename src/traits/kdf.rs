//! Defines traits for key and password derivation functions.
//!
//! 定义了密钥和密码派生函数的 trait。

use crate::errors::Error;
use crate::traits::algorithm::Algorithm;
use digest::XofReader as DigestXofReader;
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

/// A top-level trait for all derivation algorithms (KDFs, PBKDFs, etc.).
///
/// 所有派生算法（KDF、PBKDF 等）的顶层 trait。
pub trait Derivation: Algorithm {}

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
pub trait PasswordBasedDerivation: Derivation {
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
    fn derive(&self, password: &[u8], salt: &[u8], output_len: usize) -> Result<DerivedKey, Error>;
}

/// A reader for extendable-output functions (XOFs).
///
/// This struct wraps a boxed `digest::XofReader` to provide a concrete type
/// that can be returned from trait methods.
///
/// 可扩展输出函数 (XOF) 的读取器。
///
/// 此结构体包装了一个盒装的 `digest::XofReader`，以提供可从 trait 方法返回的具体类型。
pub struct XofReader<'a> {
    reader: Box<dyn DigestXofReader + 'a>,
}

impl<'a> XofReader<'a> {
    /// Creates a new `XofReader` from a boxed `digest::XofReader`.
    ///
    /// 从盒装的 `digest::XofReader` 创建一个新的 `XofReader`。
    pub fn new<R: DigestXofReader + 'a>(reader: R) -> Self {
        Self {
            reader: Box::new(reader),
        }
    }
}

impl<'a> DigestXofReader for XofReader<'a> {
    fn read(&mut self, buffer: &mut [u8]) {
        self.reader.read(buffer);
    }
}

/// A trait for Key Derivation Functions based on Extendable-Output Functions (XOFs).
///
/// This trait allows for deriving a stream of bytes from Input Keying Material (IKM),
/// which is useful for generating multiple keys or keys of a length not known beforehand.
///
/// 基于可扩展输出函数 (XOF) 的密钥派生函数 trait。
///
/// 此 trait 允许从输入密钥材料 (IKM) 派生字节流，
/// 这对于生成多个密钥或预先未知长度的密钥非常有用。
pub trait XofDerivation: Derivation {
    /// Derives a byte stream from Input Keying Material (IKM).
    ///
    /// # Arguments
    /// * `ikm` - The Input Keying Material.
    /// * `salt` - An optional salt.
    /// * `info` - Optional context and application-specific information.
    ///
    /// # Returns
    /// An `XofReader` that can be used to read an arbitrary number of bytes.
    ///
    /// 从输入密钥材料 (IKM) 派生字节流。
    ///
    /// # 参数
    /// * `ikm` - 输入密钥材料。
    /// * `salt` - 可选的盐。
    /// * `info` - 可选的上下文和应用程序特定信息。
    ///
    /// # 返回
    /// 一个可用于读取任意数量字节的 `XofReader`。
    fn reader<'a>(
        &self,
        ikm: &'a [u8],
        salt: Option<&'a [u8]>,
        info: Option<&'a [u8]>,
    ) -> Result<XofReader<'a>, Error>;
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
