//! Provides an implementation of the HMAC-based Key Derivation Function (HKDF).
//!
//! 提供了基于 HMAC 的密钥派生函数 (HKDF) 的实现。

use crate::{
    errors::Error,
    traits::{
        algorithm::Algorithm,
        hash::{Hasher, Sha256, Sha512},
        kdf::{DerivedKey, KdfError, KeyDerivation},
    },
};
use hkdf_p::Hkdf;
use std::marker::PhantomData;

// --- Generic HKDF Implementation ---
// --- 通用 HKDF 实现 ---

/// A generic struct representing the HKDF cryptographic system for a given hash function.
///
/// 一个通用的 HKDF 系统结构体，它在哈希函数上是通用的。
#[derive(Debug)]
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

impl<H: Hasher> Algorithm for HkdfScheme<H> {
    const NAME: &'static str = "HKDF";
}

// 实现针对具体哈希算法的HKDF方案，而不是通用的方案
// Implementation for specific hash algorithms instead of generic

#[cfg(feature = "sha2")]
impl KeyDerivation for HkdfScheme<Sha256> {
    fn derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<DerivedKey, Error> {
        let hk = Hkdf::<sha2::Sha256>::new(salt, ikm);
        let mut okm = vec![0u8; output_len];

        hk.expand(info.unwrap_or_default(), &mut okm)
            .map_err(|_| Error::Kdf(KdfError::InvalidOutputLength))?;

        Ok(DerivedKey::new(okm))
    }
}

#[cfg(feature = "sha2")]
impl KeyDerivation for HkdfScheme<Sha512> {
    fn derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<DerivedKey, Error> {
        let hk = Hkdf::<sha2::Sha512>::new(salt, ikm);
        let mut okm = vec![0u8; output_len];

        hk.expand(info.unwrap_or_default(), &mut okm)
            .map_err(|_| Error::Kdf(KdfError::InvalidOutputLength))?;

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

/// A type alias for the HKDF-SHA-512 scheme.
///
/// HKDF-SHA-512 方案的类型别名。
#[cfg(feature = "sha2")]
pub type HkdfSha512 = HkdfScheme<Sha512>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{hash::Hasher, kdf::KeyDerivation};

    fn run_hkdf_test<H: Hasher>()
    where
        HkdfScheme<H>: KeyDerivation + Default,
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
    fn test_hkdf_sha512() {
        run_hkdf_test::<Sha512>();
    }
}