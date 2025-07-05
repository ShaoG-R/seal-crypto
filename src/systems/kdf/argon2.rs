//! Provides an implementation of the Argon2 key derivation function.
//!
//! 提供了 Argon2 密钥派生函数的实现。

use crate::{
    errors::Error,
    traits::{
        algorithm::Algorithm,
        kdf::{Derivation, DerivedKey, KdfError, PasswordBasedDerivation},
    },
};
#[cfg(feature = "std")]
use argon2::Argon2 as Argon2_p;
use secrecy::SecretVec;

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
/// 代表 Argon2id 加密系统的结构体。
#[derive(Debug, Clone, Copy)]
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
    /// 使用指定的参数创建一个新的 Argon2 方案。
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
    /// 使用基于 OWASP 建议的默认安全参数创建一个新的 Argon2 方案。
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
    const NAME: &'static str = "Argon2id";
}

impl PasswordBasedDerivation for Argon2Scheme {
    #[cfg(feature = "std")]
    fn derive(&self, password: &SecretVec<u8>, salt: &[u8], output_len: usize) -> Result<DerivedKey, Error> {
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

    #[cfg(not(feature = "std"))]
    fn derive(
        &self,
        _password: &[u8],
        _salt: &[u8],
        _output_len: usize,
    ) -> Result<DerivedKey, Error> {
        // In a `no_std` environment, we cannot dynamically allocate the memory needed for Argon2's `m_cost`.
        // The `hash_password_into_with_memory` function requires a pre-allocated buffer, but `m_cost` is a
        // runtime parameter, making stack allocation impossible without a fixed, constant size.
        // Therefore, Argon2 derivation is not supported in `no_std` mode with the current API design.
        //
        // 在 `no_std` 环境中，我们无法为 Argon2 的 `m_cost` 动态分配所需的内存。
        // `hash_password_into_with_memory` 函数需要一个预先分配的缓冲区，但 `m_cost` 是一个运行时参数，
        // 这使得在没有固定常量大小的情况下无法进行栈分配。
        // 因此，在当前的 API 设计下，`no_std` 模式不支持 Argon2 派生。
        Err(Error::Kdf(KdfError::UnsupportedInNoStd))
    }
}

/// A type alias for the Argon2id scheme.
///
/// Argon2id 方案的类型别名。
pub type Argon2 = Argon2Scheme;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "std")]
    #[test]
    fn test_argon2_derivation_std() {
        let password = SecretVec::new(b"password".to_vec());
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

    #[cfg(not(feature = "std"))]
    #[test]
    fn test_argon2_derivation_no_std() {
        let password = SecretVec::new(b"password".to_vec());
        let salt = b"some-random-salt";
        let output_len = 32;
        let scheme = Argon2Scheme::new(16, 1, 1);

        let derived_key_result = scheme.derive(password, salt, output_len);
        assert!(derived_key_result.is_err());
        assert_eq!(
            derived_key_result.unwrap_err(),
            Error::Kdf(KdfError::UnsupportedInNoStd)
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_argon2_determinism() {
        let password = SecretVec::new(b"a-secure-password".to_vec());
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
        let password = SecretVec::new(b"another-password".to_vec());
        let salt1 = b"salt-number-one";
        let salt2 = b"salt-number-two";
        let output_len = 32;
        let scheme = Argon2Scheme::new(16, 1, 1);

        let key1 = scheme.derive(&password, salt1, output_len).unwrap();
        let key2 = scheme.derive(&password, salt2, output_len).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
