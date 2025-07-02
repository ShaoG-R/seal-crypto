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
use argon2::Argon2 as Argon2_p;

/// Argon2id default memory cost (in kibibytes). OWASP recommendation: 19 MiB = 19456 KiB.
/// We use a slightly more conservative value that is a power of 2.
pub const ARGON2_DEFAULT_M_COST: u32 = 32768; // 32 MiB

/// Argon2id default time cost (iterations). OWASP recommendation: 2.
pub const ARGON2_DEFAULT_T_COST: u32 = 2;

/// Argon2id default parallelism cost. OWASP recommendation: 1.
pub const ARGON2_DEFAULT_P_COST: u32 = 1;

/// A struct representing the Argon2id cryptographic system.
#[derive(Debug, Clone, Copy)]
pub struct Argon2Scheme {
    /// Memory cost in kibibytes.
    pub m_cost: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism cost (threads).
    pub p_cost: u32,
}

impl Argon2Scheme {
    /// Creates a new Argon2 scheme with specific parameters.
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
    fn derive(&self, password: &[u8], salt: &[u8], output_len: usize) -> Result<DerivedKey, Error> {
        let params = argon2::Params::new(self.m_cost, self.t_cost, self.p_cost, Some(output_len))
            .map_err(|_| Error::Kdf(KdfError::DerivationFailed))?;

        let argon2 = Argon2_p::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        );

        let mut output = vec![0u8; output_len];
        argon2.hash_password_into(password, salt, &mut output)
            .map_err(|_| Error::Kdf(KdfError::DerivationFailed))?;

        Ok(DerivedKey::new(output))
    }
}

/// A type alias for the Argon2id scheme.
pub type Argon2 = Argon2Scheme;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_derivation() {
        let password = b"password";
        let salt = b"some-random-salt";
        let output_len = 32;

        // Use low-cost parameters for fast testing
        let scheme = Argon2Scheme::new(16, 1, 1);

        let derived_key_result = scheme.derive(password, salt, output_len);
        assert!(derived_key_result.is_ok());

        let derived_key = derived_key_result.unwrap();
        assert_eq!(derived_key.as_bytes().len(), output_len);

        // Test with default parameters
        let default_scheme = Argon2Scheme::default();
        let derived_key_default_result = default_scheme.derive(password, salt, output_len);
        assert!(derived_key_default_result.is_ok());
    }

    #[test]
    fn test_argon2_determinism() {
        let password = b"a-secure-password";
        let salt = b"a-unique-salt-for-this-user";
        let output_len = 64;
        let scheme = Argon2Scheme::new(16, 1, 1);

        let key1 = scheme.derive(password, salt, output_len).unwrap();
        let key2 = scheme.derive(password, salt, output_len).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_argon2_different_salts() {
        let password = b"another-password";
        let salt1 = b"salt-number-one";
        let salt2 = b"salt-number-two";
        let output_len = 32;
        let scheme = Argon2Scheme::new(16, 1, 1);

        let key1 = scheme.derive(password, salt1, output_len).unwrap();
        let key2 = scheme.derive(password, salt2, output_len).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
