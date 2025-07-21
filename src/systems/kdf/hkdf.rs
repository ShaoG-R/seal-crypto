//! Provides an implementation of the HMAC-based Key Derivation Function (HKDF).
//!
//! 提供了基于 HMAC 的密钥派生函数 (HKDF) 的实现。

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
