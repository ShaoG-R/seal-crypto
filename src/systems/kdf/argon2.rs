//! Provides an implementation of the Argon2 key derivation function.
//!
//! Argon2 is a modern, memory-hard password hashing function that won the Password
//! Hashing Competition (PHC) in 2015. It is designed to be resistant to GPU-based
//! attacks, side-channel attacks, and time-memory trade-off attacks. Argon2 is
//! recommended by security experts for new applications requiring password-based
//! key derivation.
//!
//! # Algorithm Variants
//! This implementation uses **Argon2id**, which combines the benefits of both
//! Argon2i (data-independent) and Argon2d (data-dependent) variants:
//! - **Argon2i**: Resistant to side-channel attacks
//! - **Argon2d**: Resistant to time-memory trade-off attacks
//! - **Argon2id**: Combines both protections (recommended)
//!
//! # Security Properties
//! - **Memory-hard**: Requires significant memory to compute, making parallel attacks expensive
//! - **Time-tunable**: Iteration count can be adjusted for desired security/performance balance
//! - **Parallelizable**: Can utilize multiple CPU cores for faster computation
//! - **Side-channel resistant**: Argon2id variant provides protection against timing attacks
//! - **GPU-resistant**: Memory requirements make GPU-based attacks less effective
//!
//! # Parameters
//! Argon2 has three main cost parameters:
//! - **Memory cost (m_cost)**: Amount of memory used in kibibytes (KiB)
//! - **Time cost (t_cost)**: Number of iterations
//! - **Parallelism (p_cost)**: Number of parallel threads
//!
//! # Default Parameters
//! Based on OWASP recommendations (2023):
//! - **Memory cost**: 32 MiB (32,768 KiB) - conservative value that's a power of 2
//! - **Time cost**: 2 iterations - minimum recommended value
//! - **Parallelism**: 1 thread - suitable for most applications
//!
//! # Performance Considerations
//! - Higher memory cost increases resistance to parallel attacks
//! - Higher time cost increases overall computation time
//! - Parallelism can improve performance on multi-core systems
//! - Memory cost has the most significant impact on security
//!
//! # Security Recommendations
//! - Use at least 19 MiB memory cost for new applications
//! - Increase time cost if memory is limited
//! - Use unique salts for each password
//! - Consider increasing parameters as hardware improves
//! - Monitor computation time to prevent DoS attacks
//!
//! # Use Cases
//! - Password hashing for user authentication
//! - Key derivation from user passwords
//! - Protecting sensitive data with password-based encryption
//! - Applications requiring resistance to specialized hardware attacks
//! - Systems where memory-hard properties are beneficial
//!
//! # Comparison with Other KDFs
//! - **vs PBKDF2**: Argon2 is more resistant to GPU/ASIC attacks
//! - **vs scrypt**: Argon2 has better resistance to side-channel attacks
//! - **vs bcrypt**: Argon2 is more configurable and future-proof
//!
//! 提供了 Argon2 密钥派生函数的实现。
//!
//! Argon2 是一种现代的、内存困难的密码哈希函数，在 2015 年赢得了密码哈希竞赛 (PHC)。
//! 它设计为能够抵抗基于 GPU 的攻击、侧信道攻击和时间-内存权衡攻击。
//! 安全专家推荐 Argon2 用于需要基于密码的密钥派生的新应用程序。
//!
//! # 算法变体
//! 此实现使用 **Argon2id**，它结合了 Argon2i（数据无关）和 Argon2d（数据相关）变体的优点：
//! - **Argon2i**: 抵抗侧信道攻击
//! - **Argon2d**: 抵抗时间-内存权衡攻击
//! - **Argon2id**: 结合两种保护（推荐）
//!
//! # 安全属性
//! - **内存困难**: 需要大量内存来计算，使并行攻击变得昂贵
//! - **时间可调**: 可以调整迭代次数以获得所需的安全性/性能平衡
//! - **可并行化**: 可以利用多个 CPU 核心进行更快的计算
//! - **侧信道抵抗**: Argon2id 变体提供对时序攻击的保护
//! - **GPU 抵抗**: 内存要求使基于 GPU 的攻击效果较差
//!
//! # 参数
//! Argon2 有三个主要的成本参数：
//! - **内存成本 (m_cost)**: 使用的内存量（单位：KiB）
//! - **时间成本 (t_cost)**: 迭代次数
//! - **并行度 (p_cost)**: 并行线程数
//!
//! # 默认参数
//! 基于 OWASP 建议（2023）：
//! - **内存成本**: 32 MiB (32,768 KiB) - 保守的 2 的幂次方值
//! - **时间成本**: 2 次迭代 - 最小推荐值
//! - **并行度**: 1 个线程 - 适用于大多数应用程序
//!
//! # 性能考虑
//! - 更高的内存成本增加对并行攻击的抵抗力
//! - 更高的时间成本增加总体计算时间
//! - 并行度可以在多核系统上提高性能
//! - 内存成本对安全性的影响最为显著
//!
//! # 安全建议
//! - 新应用程序至少使用 19 MiB 内存成本
//! - 如果内存有限，增加时间成本
//! - 为每个密码使用唯一的盐
//! - 考虑随着硬件改进而增加参数
//! - 监控计算时间以防止 DoS 攻击
//!
//! # 使用场景
//! - 用户认证的密码哈希
//! - 从用户密码派生密钥
//! - 使用基于密码的加密保护敏感数据
//! - 需要抵抗专用硬件攻击的应用程序
//! - 内存困难属性有益的系统
//!
//! # 与其他 KDF 的比较
//! - **vs PBKDF2**: Argon2 更能抵抗 GPU/ASIC 攻击
//! - **vs scrypt**: Argon2 对侧信道攻击有更好的抵抗力
//! - **vs bcrypt**: Argon2 更可配置且更面向未来

use crate::{
    errors::Error,
    traits::{
        algorithm::Algorithm,
        kdf::{Derivation, DerivedKey, KdfError, PasswordBasedDerivation},
    },
};
use crate::traits::params::{Parameterized, ParamValue};
#[cfg(feature = "std")]
use argon2::Argon2 as Argon2_p;
use secrecy::SecretBox;

/// Argon2id default memory cost (in kibibytes). OWASP recommendation: 19 MiB = 19456 KiB.
/// We use a slightly more conservative value that is a power of 2.
///
/// Argon2id 默认内存成本（单位：KiB）。OWASP 建议值为 19 MiB = 19456 KiB。
/// 我们使用一个稍微保守的、2的幂次方的值。
pub const ARGON2_DEFAULT_M_COST: u32 = 32768; // 32 MiB

/// Argon2id default time cost (iterations). OWASP recommendation: 2.
///
/// Argon2id 默认时间成本（迭代次数）。OWASP 建议值为 2。
pub const ARGON2_DEFAULT_T_COST: u32 = 2;

/// Argon2id default parallelism cost. OWASP recommendation: 1.
///
/// Argon2id 默认并行成本。OWASP 建议值为 1。
pub const ARGON2_DEFAULT_P_COST: u32 = 1;

/// A struct representing the Argon2id cryptographic system.
///
/// This struct encapsulates the Argon2id password hashing algorithm with configurable
/// parameters for memory cost, time cost, and parallelism. It provides a secure way
/// to derive keys from passwords while being resistant to various attack vectors.
///
/// # Security Features
/// - Memory-hard function resistant to GPU/ASIC attacks
/// - Configurable parameters for security/performance tuning
/// - Side-channel attack resistance through Argon2id variant
/// - Time-memory trade-off attack resistance
///
/// # Parameter Guidelines
/// - **m_cost**: Should be as high as acceptable for your application (minimum 19 MiB)
/// - **t_cost**: Minimum 2 iterations, increase if memory is limited
/// - **p_cost**: Usually 1, can be increased for multi-core systems
///
/// 代表 Argon2id 加密系统的结构体。
///
/// 此结构体封装了 Argon2id 密码哈希算法，具有可配置的内存成本、时间成本和并行度参数。
/// 它提供了一种从密码派生密钥的安全方法，同时抵抗各种攻击向量。
///
/// # 安全特性
/// - 抵抗 GPU/ASIC 攻击的内存困难函数
/// - 用于安全性/性能调优的可配置参数
/// - 通过 Argon2id 变体抵抗侧信道攻击
/// - 抵抗时间-内存权衡攻击
///
/// # 参数指南
/// - **m_cost**: 应尽可能高，以适应您的应用程序（最少 19 MiB）
/// - **t_cost**: 最少 2 次迭代，如果内存有限可增加
/// - **p_cost**: 通常为 1，可为多核系统增加
#[derive(Clone, Debug)]
pub struct Argon2Scheme {
    /// Memory cost in kibibytes.
    ///
    /// 内存成本（单位：KiB）。
    pub m_cost: u32,
    /// Time cost (iterations).
    ///
    /// 时间成本（迭代次数）。
    pub t_cost: u32,
    /// Parallelism cost (threads).
    ///
    /// 并行成本（线程数）。
    pub p_cost: u32,
}

impl Argon2Scheme {
    /// Creates a new Argon2 scheme with specific parameters.
    ///
    /// # Arguments
    /// * `m_cost` - Memory cost in kibibytes (KiB). Minimum recommended: 19456 (19 MiB)
    /// * `t_cost` - Time cost (iterations). Minimum recommended: 2
    /// * `p_cost` - Parallelism (number of threads). Usually 1, can be higher for multi-core
    ///
    /// # Security Considerations
    /// - Higher memory cost provides better security against parallel attacks
    /// - Higher time cost increases computation time linearly
    /// - Parallelism should match available CPU cores for optimal performance
    ///
    /// 使用指定的参数创建一个新的 Argon2 方案。
    ///
    /// # 参数
    /// * `m_cost` - 内存成本（单位：KiB）。最小推荐值：19456 (19 MiB)
    /// * `t_cost` - 时间成本（迭代次数）。最小推荐值：2
    /// * `p_cost` - 并行度（线程数）。通常为 1，多核系统可以更高
    ///
    /// # 安全考虑
    /// - 更高的内存成本对并行攻击提供更好的安全性
    /// - 更高的时间成本线性增加计算时间
    /// - 并行度应匹配可用的 CPU 核心以获得最佳性能
    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
        Self {
            m_cost,
            t_cost,
            p_cost,
        }
    }
}

impl Default for Argon2Scheme {
    /// Creates a new Argon2 scheme with default security parameters based on OWASP recommendations.
    ///
    /// The default parameters provide a good balance between security and performance:
    /// - Memory cost: 32 MiB (conservative, power-of-2 value)
    /// - Time cost: 2 iterations (minimum recommended)
    /// - Parallelism: 1 thread (suitable for most applications)
    ///
    /// These parameters should provide adequate security for most applications while
    /// maintaining reasonable performance. Consider increasing parameters for
    /// high-security applications or as hardware improves.
    ///
    /// 使用基于 OWASP 建议的默认安全参数创建一个新的 Argon2 方案。
    ///
    /// 默认参数在安全性和性能之间提供良好的平衡：
    /// - 内存成本：32 MiB（保守的 2 的幂次方值）
    /// - 时间成本：2 次迭代（最小推荐值）
    /// - 并行度：1 个线程（适用于大多数应用程序）
    ///
    /// 这些参数应该为大多数应用程序提供足够的安全性，同时保持合理的性能。
    /// 对于高安全性应用程序或随着硬件改进，考虑增加参数。
    fn default() -> Self {
        Self::new(
            ARGON2_DEFAULT_M_COST,
            ARGON2_DEFAULT_T_COST,
            ARGON2_DEFAULT_P_COST,
        )
    }
}

impl Derivation for Argon2Scheme {}

impl Algorithm for Argon2Scheme {
    fn name() -> String {
        "Argon2id".to_string()
    }
    const ID: u32 = 0x03_01_01_01;
}

impl Parameterized for Argon2Scheme {
    fn get_type_params() -> Vec<(&'static str, ParamValue)> {
        vec![]
    }

    fn get_instance_params(&self) -> Vec<(&'static str, ParamValue)> {
        vec![
            ("m_cost", ParamValue::U32(self.m_cost)),
            ("t_cost", ParamValue::U32(self.t_cost)),
            ("p_cost", ParamValue::U32(self.p_cost)),
        ]
    }
}

impl PasswordBasedDerivation for Argon2Scheme {
    fn derive(
        &self,
        password: &SecretBox<[u8]>,
        salt: &[u8],
        output_len: usize,
    ) -> Result<DerivedKey, Error> {
        use secrecy::ExposeSecret;

        let params = argon2::Params::new(self.m_cost, self.t_cost, self.p_cost, Some(output_len))
            .map_err(|_| Error::Kdf(KdfError::DerivationFailed))?;

        let argon2 = Argon2_p::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        // Directly hash the password with the raw salt into an output buffer.
        // This is the most direct way to use Argon2 for key derivation.
        //
        // 直接使用原始盐和密码将哈希值计算到输出缓冲区中。
        // 这是将 Argon2 用于密钥派生的最直接方法。
        let mut output = vec![0u8; output_len];
        argon2
            .hash_password_into(password.expose_secret(), salt, &mut output)
            .map_err(|_| Error::Kdf(KdfError::DerivationFailed))?;

        Ok(DerivedKey::new(output))
    }
}

/// A type alias for the Argon2id scheme.
///
/// Argon2id 方案的类型别名。
pub type Argon2 = Argon2Scheme;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_derivation_std() {
        let password = SecretBox::new(Box::from(b"password".as_slice()));
        let salt = b"some-random-salt";
        let output_len = 32;

        // Use low-cost parameters for fast testing
        let scheme = Argon2Scheme::new(16, 1, 1);

        let derived_key_result = scheme.derive(&password, salt, output_len);
        assert!(derived_key_result.is_ok());

        let derived_key = derived_key_result.unwrap();
        assert_eq!(derived_key.as_bytes().len(), output_len);

        // Test with default parameters
        let default_scheme = Argon2Scheme::default();
        let derived_key_default_result = default_scheme.derive(&password, salt, output_len);
        assert!(derived_key_default_result.is_ok());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_argon2_determinism() {
        let password = SecretBox::new(Box::from(b"a-secure-password".as_slice()));
        let salt = b"a-unique-salt-for-this-user";
        let output_len = 64;
        let scheme = Argon2Scheme::new(16, 1, 1);

        let key1 = scheme.derive(&password, salt, output_len).unwrap();
        let key2 = scheme.derive(&password, salt, output_len).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_argon2_different_salts() {
        let password = SecretBox::new(Box::from(b"another-password".as_slice()));
        let salt1 = b"salt-number-one";
        let salt2 = b"salt-number-two";
        let output_len = 32;
        let scheme = Argon2Scheme::new(16, 1, 1);

        let key1 = scheme.derive(&password, salt1, output_len).unwrap();
        let key2 = scheme.derive(&password, salt2, output_len).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_argon2_generate_salt() {
        let scheme = Argon2Scheme::default();
        let salt_result = scheme.generate_salt();
        assert!(salt_result.is_ok());
        let salt = salt_result.unwrap();
        assert_eq!(
            salt.len(),
            <Argon2Scheme as PasswordBasedDerivation>::RECOMMENDED_SALT_LENGTH
        );

        // Generate another salt to ensure they are not identical
        let salt2 = scheme.generate_salt().unwrap();
        assert_ne!(
            salt, salt2,
            "Generated salts should be random and not identical"
        );
    }
}
