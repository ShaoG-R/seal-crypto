//! Provides an implementation of the Password-Based Key Derivation Function 2 (PBKDF2).
//!
//! PBKDF2 is a key derivation function designed for deriving cryptographic keys from
//! low-entropy passwords. It is defined in RFC 2898 and PKCS #5, and is widely used
//! for password-based cryptography.
//!
//! # Algorithm Overview
//! PBKDF2 applies a pseudorandom function (typically HMAC) iteratively to the password
//! and salt, making brute-force attacks computationally expensive. The iteration count
//! can be adjusted to increase the computational cost as hardware improves.
//!
//! # Security Properties
//! - Resistant to dictionary and brute-force attacks through iteration count
//! - Salt prevents rainbow table attacks
//! - Widely studied and standardized
//! - Suitable for password-based key derivation
//!
//! # Parameters
//! - **Password**: The user's password (low-entropy input)
//! - **Salt**: Random salt value (must be unique per password)
//! - **Iterations**: Number of iterations (higher = more secure but slower)
//! - **Length**: Desired length of derived key
//!
//! # Iteration Count Guidelines
//! - Minimum 100,000 iterations for new applications (as of 2023)
//! - OWASP recommends 600,000 iterations for PBKDF2-HMAC-SHA256
//! - Adjust based on acceptable delay and security requirements
//! - Consider using Argon2 for new applications requiring higher security
//!
//! # Security Considerations
//! - Use cryptographically random salts
//! - Salt should be at least 128 bits (16 bytes)
//! - Iteration count should be as high as acceptable for your use case
//! - Consider memory-hard functions like Argon2 for higher security
//! - Protect derived keys with the same care as the original password
//!
//! # Performance vs Security Trade-off
//! Higher iteration counts provide better security but increase computation time.
//! The default iteration count is set to provide reasonable security while
//! maintaining acceptable performance for most applications.
//!
//! 提供了基于密码的密钥派生函数 2 (PBKDF2) 的实现。
//!
//! PBKDF2 是一种密钥派生函数，设计用于从低熵密码派生加密密钥。
//! 它在 RFC 2898 和 PKCS #5 中定义，广泛用于基于密码的密码学。
//!
//! # 算法概述
//! PBKDF2 对密码和盐迭代应用伪随机函数（通常是 HMAC），使暴力破解攻击在计算上变得昂贵。
//! 迭代次数可以调整以随着硬件改进而增加计算成本。
//!
//! # 安全属性
//! - 通过迭代次数抵抗字典和暴力破解攻击
//! - 盐防止彩虹表攻击
//! - 经过广泛研究和标准化
//! - 适用于基于密码的密钥派生
//!
//! # 参数
//! - **Password**: 用户的密码（低熵输入）
//! - **Salt**: 随机盐值（每个密码必须唯一）
//! - **Iterations**: 迭代次数（更高 = 更安全但更慢）
//! - **Length**: 派生密钥的期望长度
//!
//! # 迭代次数指南
//! - 新应用程序最少 100,000 次迭代（截至 2023 年）
//! - OWASP 推荐 PBKDF2-HMAC-SHA256 使用 600,000 次迭代
//! - 根据可接受的延迟和安全要求进行调整
//! - 对于需要更高安全性的新应用程序，考虑使用 Argon2
//!
//! # 安全考虑
//! - 使用加密随机盐
//! - 盐应至少为 128 位（16 字节）
//! - 迭代次数应尽可能高，以适应您的使用场景
//! - 对于更高的安全性，考虑使用像 Argon2 这样的内存困难函数
//! - 保护派生密钥时应与保护原始密码一样小心
//!
//! # 性能与安全性权衡
//! 更高的迭代次数提供更好的安全性，但会增加计算时间。
//! 默认迭代次数设置为在为大多数应用程序保持可接受性能的同时提供合理的安全性。

use crate::{
    errors::Error,
    prelude::*
};
use crate::traits::params::{ParamValue, Parameterized};
use secrecy::{ExposeSecret, SecretBox};
use std::marker::PhantomData;

// A reasonable default for iterations, based on OWASP recommendations.
// For high-security applications, this value should be tuned.
// 基于 OWASP 建议的一个合理的默认迭代次数。
// 对于高安全性的应用，此值应进行调整。
pub const PBKDF2_DEFAULT_ITERATIONS: u32 = 600_000;

/// A generic struct representing the PBKDF2 cryptographic system for a given hash function.
///
/// 一个通用的 PBKDF2 系统结构体，它在哈希函数上是通用的。
#[derive(Clone, Debug)]
pub struct Pbkdf2Scheme<H: Hasher> {
    pub iterations: u32,
    _hasher: PhantomData<H>,
}

impl<H: Hasher> Pbkdf2Scheme<H> {
    /// Creates a new PBKDF2 scheme with a specific iteration count.
    ///
    /// 使用指定的迭代次数创建一个新的 PBKDF2 方案。
    pub fn new(iterations: u32) -> Self {
        Self {
            iterations,
            _hasher: PhantomData,
        }
    }
}

impl<H: Hasher> Default for Pbkdf2Scheme<H> {
    /// Creates a new PBKDF2 scheme with the default number of iterations.
    ///
    /// 使用默认迭代次数创建一个新的 PBKDF2 方案。
    fn default() -> Self {
        Self::new(PBKDF2_DEFAULT_ITERATIONS)
    }
}

impl<H: Hasher> Derivation for Pbkdf2Scheme<H> {}

impl<H: Hasher> Algorithm for Pbkdf2Scheme<H> {
    fn name() -> String {
        format!("PBKDF2-HMAC-{}", H::NAME)
    }
    const ID: u32 = 0x03_03_00_00 + H::ID_OFFSET;
}

impl<H: Hasher> Parameterized for Pbkdf2Scheme<H> {
    fn get_type_params() -> Vec<(&'static str, ParamValue)> {
        vec![("hash", ParamValue::String(H::NAME.to_string()))]
    }

    fn get_instance_params(&self) -> Vec<(&'static str, ParamValue)> {
        vec![("iterations", ParamValue::U32(self.iterations))]
    }
}

impl<H: Hasher> PasswordBasedDerivation for Pbkdf2Scheme<H> {
    fn derive(
        &self,
        password: &SecretBox<[u8]>,
        salt: &[u8],
        output_len: usize,
    ) -> Result<DerivedKey, Error> {
        let mut okm = vec![0u8; output_len];

        H::pbkdf2_hmac(password.expose_secret(), salt, self.iterations, &mut okm);

        Ok(DerivedKey::new(okm))
    }
}

// --- Type Aliases ---
// --- 类型别名 ---
#[cfg(feature = "sha2")]
pub type Pbkdf2<H> = Pbkdf2Scheme<H>;

/// A type alias for the PBKDF2-HMAC-SHA-256 scheme.
///
/// PBKDF2-HMAC-SHA-256 方案的类型别名。
#[cfg(feature = "sha2")]
pub type Pbkdf2Sha256 = Pbkdf2Scheme<Sha256>;

/// A type alias for the PBKDF2-HMAC-SHA-384 scheme.
///
/// PBKDF2-HMAC-SHA-384 方案的类型别名。
#[cfg(feature = "sha2")]
pub type Pbkdf2Sha384 = Pbkdf2Scheme<Sha384>;

/// A type alias for the PBKDF2-HMAC-SHA-512 scheme.
///
/// PBKDF2-HMAC-SHA-512 方案的类型别名。
#[cfg(feature = "sha2")]
pub type Pbkdf2Sha512 = Pbkdf2Scheme<Sha512>;

#[cfg(test)]
mod tests {
    use super::*;

    fn run_pbkdf2_test<H: Hasher>()
    where
        Pbkdf2Scheme<H>: PasswordBasedDerivation,
    {
        let password = SecretBox::new(Box::from(b"password".as_slice()));
        let salt = b"salt";
        let output_len = 32;
        let custom_iterations = 1000; // Use a low number for fast tests

        // Test with a custom iteration count
        let scheme_custom = Pbkdf2Scheme::<H>::new(custom_iterations);
        let derived_key_result_custom = scheme_custom.derive(&password, salt, output_len);
        assert!(derived_key_result_custom.is_ok());
        let derived_key_custom = derived_key_result_custom.unwrap();
        assert_eq!(derived_key_custom.as_bytes().len(), output_len);

        // Test with default iteration count
        let scheme_default = Pbkdf2Scheme::<H>::default();
        let derived_key_result_default = scheme_default.derive(&password, salt, output_len);
        assert!(derived_key_result_default.is_ok());

        // Test without salt is no longer needed, as the function signature enforces it.
    }

    fn run_pbkdf2_generate_salt_test<H: Hasher>()
    where
        Pbkdf2Scheme<H>: PasswordBasedDerivation,
    {
        let scheme = Pbkdf2Scheme::<H>::default();
        let salt_result = scheme.generate_salt();
        assert!(salt_result.is_ok());
        let salt = salt_result.unwrap();
        assert_eq!(
            salt.len(),
            <Pbkdf2Scheme<H> as PasswordBasedDerivation>::RECOMMENDED_SALT_LENGTH
        );

        // Generate another salt to ensure they are not identical
        let salt2 = scheme.generate_salt().unwrap();
        assert_ne!(
            salt, salt2,
            "Generated salts should be random and not identical"
        );
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_pbkdf2_sha256() {
        run_pbkdf2_test::<Sha256>();
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_pbkdf2_sha384() {
        run_pbkdf2_test::<Sha384>();
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_pbkdf2_sha512() {
        run_pbkdf2_test::<Sha512>();
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_pbkdf2_sha256_generate_salt() {
        run_pbkdf2_generate_salt_test::<Sha256>();
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_pbkdf2_sha384_generate_salt() {
        run_pbkdf2_generate_salt_test::<Sha384>();
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_pbkdf2_sha512_generate_salt() {
        run_pbkdf2_generate_salt_test::<Sha512>();
    }
}
