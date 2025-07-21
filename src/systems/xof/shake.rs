//! Provides an implementation of the SHAKE (Secure Hash Algorithm and Keccak) family of Extendable-Output Functions (XOFs).
//!
//! SHAKE functions are part of the SHA-3 family and are based on the Keccak sponge construction.
//! Unlike traditional hash functions that produce fixed-length outputs, XOFs can produce
//! variable-length outputs, making them suitable for applications requiring flexible
//! output lengths.
//!
//! # Algorithm Variants
//! - **SHAKE128**: Provides 128 bits of security strength
//! - **SHAKE256**: Provides 256 bits of security strength
//!
//! # Sponge Construction
//! SHAKE functions use the Keccak sponge construction, which consists of:
//! 1. **Absorbing Phase**: Input data is absorbed into the internal state
//! 2. **Squeezing Phase**: Output is squeezed from the internal state
//!
//! # Security Properties
//! - Provides strong security guarantees based on the Keccak construction
//! - Resistant to known cryptanalytic attacks
//! - Security level remains constant regardless of output length
//! - Suitable for generating cryptographic keys and random values
//!
//! # Use Cases
//! - Key derivation when variable output length is needed
//! - Generating multiple keys from a single input
//! - Random number generation
//! - Domain separation in cryptographic protocols
//! - Applications requiring arbitrary-length hash outputs
//!
//! # Performance Characteristics
//! - Efficient software implementation
//! - Good performance on both small and large inputs
//! - Suitable for both high-performance and embedded applications
//! - No patent restrictions
//!
//! # Security Considerations
//! - Choose appropriate security level (SHAKE128 vs SHAKE256)
//! - Use domain separation when deriving multiple keys
//! - Output length can be arbitrary but should match security requirements
//! - Consider using salt for additional security in key derivation
//!
//! 提供了 SHAKE (安全哈希算法和 Keccak) 系列的可扩展输出函数 (XOFs) 的实现。
//!
//! SHAKE 函数是 SHA-3 系列的一部分，基于 Keccak 海绵结构。
//! 与产生固定长度输出的传统哈希函数不同，XOF 可以产生可变长度的输出，
//! 使其适用于需要灵活输出长度的应用程序。
//!
//! # 算法变体
//! - **SHAKE128**: 提供 128 位的安全强度
//! - **SHAKE256**: 提供 256 位的安全强度
//!
//! # 海绵结构
//! SHAKE 函数使用 Keccak 海绵结构，包括：
//! 1. **吸收阶段**: 输入数据被吸收到内部状态中
//! 2. **挤压阶段**: 从内部状态中挤压输出
//!
//! # 安全属性
//! - 基于 Keccak 结构提供强安全保证
//! - 抵抗已知的密码分析攻击
//! - 无论输出长度如何，安全级别保持恒定
//! - 适用于生成加密密钥和随机值
//!
//! # 使用场景
//! - 需要可变输出长度时的密钥派生
//! - 从单个输入生成多个密钥
//! - 随机数生成
//! - 密码协议中的域分离
//! - 需要任意长度哈希输出的应用程序
//!
//! # 性能特征
//! - 高效的软件实现
//! - 在小型和大型输入上都有良好的性能
//! - 适用于高性能和嵌入式应用程序
//! - 无专利限制
//!
//! # 安全考虑
//! - 选择适当的安全级别（SHAKE128 vs SHAKE256）
//! - 在派生多个密钥时使用域分离
//! - 输出长度可以是任意的，但应匹配安全要求
//! - 在密钥派生中考虑使用盐以获得额外的安全性

use crate::{
    errors::Error,
    prelude::*,
};
use std::marker::PhantomData;

/// A generic struct representing the SHAKE cryptographic system for a given XOF.
///
/// This struct implements key derivation functionality using SHAKE extendable-output functions.
/// It provides a unified interface for both SHAKE128 and SHAKE256, allowing users to derive
/// keys of arbitrary length from input keying material.
///
/// # Type Parameters
/// * `X` - The specific SHAKE variant (SHAKE128 or SHAKE256)
///
/// # Features
/// - Variable-length output generation
/// - Domain separation through context information
/// - Salt support for additional security
/// - Efficient streaming interface for large outputs
///
/// 一个通用的 SHAKE 系统结构体，它在 XOF 上是通用的。
///
/// 此结构体使用 SHAKE 可扩展输出函数实现密钥派生功能。
/// 它为 SHAKE128 和 SHAKE256 提供统一接口，允许用户从输入密钥材料派生任意长度的密钥。
///
/// # 类型参数
/// * `X` - 特定的 SHAKE 变体（SHAKE128 或 SHAKE256）
///
/// # 特性
/// - 可变长度输出生成
/// - 通过上下文信息进行域分离
/// - 支持盐以获得额外安全性
/// - 用于大输出的高效流接口
#[derive(Clone, Debug, Default)]
pub struct ShakeScheme<X: Xof> {
    _xof: PhantomData<X>,
}

impl<X: Xof> Derivation for ShakeScheme<X> {}

impl<X: Xof> Algorithm for ShakeScheme<X> {
    fn name() -> String {
        X::NAME.to_string()
    }
    const ID: u32 = 0x05_01_00_00 + X::ID_OFFSET;
}

impl<X: Xof> Parameterized for ShakeScheme<X> {
    fn get_type_params() -> Vec<(&'static str, ParamValue)> {
        vec![("xof", ParamValue::String(X::NAME.to_string()))]
    }

    fn get_instance_params(&self) -> Vec<(&'static str, ParamValue)> {
        vec![]
    }
}

impl<X: Xof> KeyBasedDerivation for ShakeScheme<X> {
    fn derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<DerivedKey, Error> {
        let mut reader = X::new_xof_reader(ikm, salt, info);
        let mut okm = vec![0u8; output_len];
        reader.read(&mut okm);

        Ok(DerivedKey::new(okm))
    }
}

impl<X: Xof> XofDerivation for ShakeScheme<X> {
    fn reader<'a>(
        &self,
        ikm: &'a [u8],
        salt: Option<&'a [u8]>,
        info: Option<&'a [u8]>,
    ) -> Result<XofReader<'a>, Error> {
        let reader = X::new_xof_reader(ikm, salt, info);
        Ok(XofReader::from_boxed(reader))
    }
}

// --- Type Aliases ---
// --- 类型别名 ---

/// A type alias for the SHAKE-128 scheme.
///
/// SHAKE-128 方案的类型别名。
pub type Shake128 = ShakeScheme<crate::traits::params::xof::Shake128>;

/// A type alias for the SHAKE-256 scheme.
///
/// SHAKE-256 方案的类型别名。
pub type Shake256 = ShakeScheme<crate::traits::params::xof::Shake256>;

#[cfg(test)]
mod tests {
    use super::*;

    fn run_shake_test<X: Xof + Default>() {
        let ikm = b"initial-keying-material";
        let salt = b"test-salt";
        let info = b"test-info";
        let output_len = 64; // XOFs can generate arbitrary length output

        let scheme = ShakeScheme::<X>::default();

        // Test with all parameters
        let derived_key_result = scheme.derive(ikm, Some(salt), Some(info), output_len);
        assert!(derived_key_result.is_ok());
        let derived_key = derived_key_result.unwrap();
        assert_eq!(derived_key.as_bytes().len(), output_len);

        // Test with different parameters
        let derived_key_no_salt_result = scheme.derive(ikm, None, Some(info), output_len);
        assert!(derived_key_no_salt_result.is_ok());

        let derived_key_no_info_result = scheme.derive(ikm, Some(salt), None, output_len);
        assert!(derived_key_no_info_result.is_ok());

        let derived_key_only_ikm_result = scheme.derive(ikm, None, None, output_len);
        assert!(derived_key_only_ikm_result.is_ok());

        // Test that outputs are different for different inputs
        let key1 = derived_key_no_salt_result.unwrap();
        let key2 = derived_key_no_info_result.unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_shake128() {
        run_shake_test::<crate::traits::params::xof::Shake128>();
    }

    #[test]
    fn test_shake256() {
        run_shake_test::<crate::traits::params::xof::Shake256>();
    }

    #[test]
    fn test_shake_xof_derivation() {
        let ikm = b"another-ikm";
        let salt = b"another-salt";
        let info = b"another-info";

        let scheme = Shake256::default();

        let reader_result = scheme.reader(ikm, Some(salt), Some(info));
        assert!(reader_result.is_ok());
        let mut reader = reader_result.unwrap();

        let mut key1 = [0u8; 32];
        reader.read(&mut key1);

        let mut key2 = [0u8; 64];
        reader.read(&mut key2);

        // Ensure the two keys are different
        assert_ne!(&key1[..], &key2[..32]);

        // Re-create the reader and check for determinism
        let mut reader2 = scheme.reader(ikm, Some(salt), Some(info)).unwrap();
        let mut key1_redux = [0u8; 32];
        reader2.read(&mut key1_redux);
        assert_eq!(&key1[..], &key1_redux[..]);
    }
}
