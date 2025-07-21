//! Provides an implementation of the HMAC-based Key Derivation Function (HKDF).
//!
//! HKDF is a key derivation function designed for deriving cryptographic keys from
//! high-entropy input keying material (IKM). It is defined in RFC 5869 and consists
//! of two phases: Extract and Expand.
//!
//! # Algorithm Overview
//! 1. **Extract Phase**: Extracts a pseudorandom key (PRK) from the input keying material
//! 2. **Expand Phase**: Expands the PRK into the desired output keying material (OKM)
//!
//! # Security Properties
//! - Provides strong security guarantees when used with high-entropy input
//! - Resistant to known cryptanalytic attacks
//! - Based on the security of the underlying HMAC construction
//! - Suitable for deriving multiple keys from a single master secret
//!
//! # Use Cases
//! - Deriving encryption keys from shared secrets (e.g., from ECDH)
//! - Key expansion in cryptographic protocols (e.g., TLS)
//! - Generating multiple keys from a single master key
//! - Converting non-uniform random material into uniform keys
//!
//! # Parameters
//! - **IKM**: Input Keying Material (should have high entropy)
//! - **Salt**: Optional salt value (recommended for security)
//! - **Info**: Optional context and application-specific information
//! - **Length**: Desired length of output keying material
//!
//! # Security Considerations
//! - Input keying material should have sufficient entropy
//! - Use unique salts when possible to prevent rainbow table attacks
//! - Context information helps domain separation
//! - Output length should not exceed 255 * hash_length
//!
//! 提供了基于 HMAC 的密钥派生函数 (HKDF) 的实现。
//!
//! HKDF 是一种密钥派生函数，设计用于从高熵输入密钥材料 (IKM) 派生加密密钥。
//! 它在 RFC 5869 中定义，包含两个阶段：提取和扩展。
//!
//! # 算法概述
//! 1. **提取阶段**: 从输入密钥材料中提取伪随机密钥 (PRK)
//! 2. **扩展阶段**: 将 PRK 扩展为所需的输出密钥材料 (OKM)
//!
//! # 安全属性
//! - 在与高熵输入一起使用时提供强安全保证
//! - 抵抗已知的密码分析攻击
//! - 基于底层 HMAC 构造的安全性
//! - 适用于从单个主密钥派生多个密钥
//!
//! # 使用场景
//! - 从共享密钥派生加密密钥（例如，从 ECDH）
//! - 密码协议中的密钥扩展（例如，TLS）
//! - 从单个主密钥生成多个密钥
//! - 将非均匀随机材料转换为均匀密钥
//!
//! # 参数
//! - **IKM**: 输入密钥材料（应具有高熵）
//! - **Salt**: 可选的盐值（推荐用于安全性）
//! - **Info**: 可选的上下文和应用程序特定信息
//! - **Length**: 输出密钥材料的期望长度
//!
//! # 安全考虑
//! - 输入密钥材料应具有足够的熵
//! - 尽可能使用唯一的盐以防止彩虹表攻击
//! - 上下文信息有助于域分离
//! - 输出长度不应超过 255 * hash_length

use crate::{
    errors::Error,
    prelude::*
};
use crate::traits::params::{ParamValue, Parameterized};
use std::marker::PhantomData;
// --- Generic HKDF Implementation ---
// --- 通用 HKDF 实现 ---

/// A generic struct representing the HKDF cryptographic system for a given hash function.
///
/// 一个通用的 HKDF 系统结构体，它在哈希函数上是通用的。
#[derive(Clone, Debug)]
pub struct HkdfScheme<H: Hasher> {
    _hasher: PhantomData<H>,
}

impl<H: Hasher> Default for HkdfScheme<H> {
    fn default() -> Self {
        Self {
            _hasher: PhantomData,
        }
    }
}

impl<H: Hasher> Derivation for HkdfScheme<H> {}

impl<H: Hasher> Algorithm for HkdfScheme<H> {
    fn name() -> String {
        format!("HKDF-{}", H::NAME)
    }
    const ID: u32 = 0x03_02_00_00 + H::ID_OFFSET;
}

impl<H: Hasher> Parameterized for HkdfScheme<H> {
    fn get_type_params() -> Vec<(&'static str, ParamValue)> {
        vec![("hash", ParamValue::String(H::NAME.to_string()))]
    }

    fn get_instance_params(&self) -> Vec<(&'static str, ParamValue)> {
        vec![]
    }
}

impl<H: Hasher> KeyBasedDerivation for HkdfScheme<H> {
    fn derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<DerivedKey, Error> {
        let mut okm = vec![0u8; output_len];
        H::hkdf_expand(salt, ikm, info, &mut okm).map_err(Error::Kdf)?;
        Ok(DerivedKey::new(okm))
    }
}

// --- Type Aliases ---
// --- 类型别名 ---

/// A type alias for the HKDF-SHA-256 scheme.
///
/// HKDF-SHA-256 方案的类型别名。
#[cfg(feature = "sha2")]
pub type HkdfSha256 = HkdfScheme<Sha256>;

/// A type alias for the HKDF-SHA-384 scheme.
///
/// HKDF-SHA-384 方案的类型别名。
#[cfg(feature = "sha2")]
pub type HkdfSha384 = HkdfScheme<Sha384>;

/// A type alias for the HKDF-SHA-512 scheme.
///
/// HKDF-SHA-512 方案的类型别名。
#[cfg(feature = "sha2")]
pub type HkdfSha512 = HkdfScheme<Sha512>;

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use super::*;

    fn run_hkdf_test<H: Hasher>()
    where
        HkdfScheme<H>: KeyBasedDerivation + Default,
    {
        let ikm = b"initial-keying-material";
        let salt = b"test-salt";
        let info = b"test-info";
        let output_len = 32;

        let scheme = HkdfScheme::<H>::default();

        let derived_key_result = scheme.derive(ikm, Some(salt), Some(info), output_len);
        assert!(derived_key_result.is_ok());

        let derived_key = derived_key_result.unwrap();
        assert_eq!(derived_key.as_bytes().len(), output_len);

        // Test with different parameters
        let derived_key_no_salt_result = scheme.derive(ikm, None, Some(info), output_len);
        assert!(derived_key_no_salt_result.is_ok());

        let derived_key_no_info_result = scheme.derive(ikm, Some(salt), None, output_len);
        assert!(derived_key_no_info_result.is_ok());
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_hkdf_sha256() {
        run_hkdf_test::<Sha256>();
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_hkdf_sha384() {
        run_hkdf_test::<Sha384>();
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_hkdf_sha512() {
        run_hkdf_test::<Sha512>();
    }
}
