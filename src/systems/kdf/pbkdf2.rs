//! Provides an implementation of the Password-Based Key Derivation Function 2 (PBKDF2).
//!
//! 提供了基于密码的密钥派生函数 2 (PBKDF2) 的实现。

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
