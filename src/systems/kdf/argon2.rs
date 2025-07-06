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
