//! Provides an implementation of the SHAKE (Secure Hash Algorithm and Keccak) family of Extendable-Output Functions (XOFs).
//!
//! 提供了 SHAKE (安全哈希算法和 Keccak) 系列的可扩展输出函数 (XOFs) 的实现。

use crate::{
    errors::Error,
    traits::{
        algorithm::Algorithm,
        hash::Xof,
        kdf::{Derivation, DerivedKey, KeyBasedDerivation},
        xof::{XofDerivation, XofReader},
    },
};
use digest::{ExtendableOutput, Update, XofReader as DigestXofReader};
use std::marker::PhantomData;

/// A generic struct representing the SHAKE cryptographic system for a given XOF.
///
/// 一个通用的 SHAKE 系统结构体，它在 XOF 上是通用的。
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

impl<X: Xof> KeyBasedDerivation for ShakeScheme<X> {
    fn derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<DerivedKey, Error> {
        let mut xof = X::Xof::default();

        if let Some(s) = salt {
            xof.update(s);
        }
        xof.update(ikm);
        if let Some(i) = info {
            xof.update(i);
        }

        let mut okm = vec![0u8; output_len];
        xof.finalize_xof().read(&mut okm);

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
        let mut xof = X::Xof::default();

        if let Some(s) = salt {
            xof.update(s);
        }
        xof.update(ikm);
        if let Some(i) = info {
            xof.update(i);
        }

        Ok(XofReader::new(xof.finalize_xof()))
    }
}

// --- Type Aliases ---
// --- 类型别名 ---

/// A type alias for the SHAKE-128 scheme.
///
/// SHAKE-128 方案的类型别名。
pub type Shake128 = ShakeScheme<crate::traits::hash::Shake128>;

/// A type alias for the SHAKE-256 scheme.
///
/// SHAKE-256 方案的类型别名。
pub type Shake256 = ShakeScheme<crate::traits::hash::Shake256>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::hash::Xof;

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
        run_shake_test::<crate::traits::hash::Shake128>();
    }

    #[test]
    fn test_shake256() {
        run_shake_test::<crate::traits::hash::Shake256>();
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
