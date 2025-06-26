//! Provides an implementation of symmetric AEAD encryption using AES-GCM.
//!
//! 提供了使用 AES-GCM 的对称 AEAD 加密实现。

use crate::errors::Error;
use crate::traits::{
    Algorithm, AssociatedData, SymmetricCipher, SymmetricDecryptor, SymmetricEncryptor,
    SymmetricError, SymmetricKey, SymmetricKeyGenerator, SymmetricKeySet,
};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{Aes128Gcm as Aes128GcmCore, Aes256Gcm as Aes256GcmCore, Nonce as NonceCore};
use std::marker::PhantomData;

// ------------------- Marker Structs and Trait for AES-GCM Parameters -------------------
// ------------------- 用于 AES-GCM 参数的标记结构体和 Trait -------------------

mod private {
    pub trait Sealed {}
}

/// A sealed trait that defines the parameters for an AES-GCM scheme.
///
/// 一个密封的 trait，用于定义 AES-GCM 方案的参数。
pub trait AesGcmParams: private::Sealed + Send + Sync + 'static {
    /// The unique name of the signature algorithm (e.g., "AES-128-GCM").
    ///
    /// 签名算法的唯一名称（例如，"AES-128-GCM"）。
    const NAME: &'static str;
    /// The underlying `aes_gcm` AEAD cipher type.
    ///
    /// 底层的 `aes_gcm` AEAD 密码类型。
    type AeadCipher: Aead + KeyInit;
    /// The size of the key in bytes.
    ///
    /// 密钥的大小（以字节为单位）。
    const KEY_SIZE: usize;
    /// The size of the nonce in bytes.
    ///
    /// Nonce 的大小（以字节为单位）。
    const NONCE_SIZE: usize;
    /// The size of the authentication tag in bytes.
    ///
    /// 认证标签的大小（以字节为单位）。
    const TAG_SIZE: usize;
}

/// Marker struct for AES-128-GCM.
///
/// AES-128-GCM 的标记结构体。
#[derive(Debug, Default)]
pub struct Aes128GcmParams;
impl private::Sealed for Aes128GcmParams {}
impl AesGcmParams for Aes128GcmParams {
    const NAME: &'static str = "AES-128-GCM";
    type AeadCipher = Aes128GcmCore;
    const KEY_SIZE: usize = 16;
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;
}

/// Marker struct for AES-256-GCM.
///
/// AES-256-GCM 的标记结构体。
#[derive(Debug, Default)]
pub struct Aes256GcmParams;
impl private::Sealed for Aes256GcmParams {}
impl AesGcmParams for Aes256GcmParams {
    const NAME: &'static str = "AES-256-GCM";
    type AeadCipher = Aes256GcmCore;
    const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;
}

// ------------------- Generic AES-GCM Implementation -------------------
// ------------------- 通用 AES-GCM 实现 -------------------

/// A generic struct representing the AES-GCM cryptographic system for a given parameter set.
///
/// 一个通用结构体，表示给定参数集的 AES-GCM 密码系统。
#[derive(Debug, Default)]
pub struct AesGcmScheme<P: AesGcmParams> {
    _params: PhantomData<P>,
}

impl<P: AesGcmParams> Algorithm for AesGcmScheme<P> {
    const NAME: &'static str = P::NAME;
}

impl<P: AesGcmParams> SymmetricKeySet for AesGcmScheme<P> {
    type Key = SymmetricKey;
}

impl<P: AesGcmParams> SymmetricCipher for AesGcmScheme<P> {
    const KEY_SIZE: usize = P::KEY_SIZE;
    const NONCE_SIZE: usize = P::NONCE_SIZE;
    const TAG_SIZE: usize = P::TAG_SIZE;
}

impl<P: AesGcmParams> SymmetricKeyGenerator for AesGcmScheme<P> {
    const KEY_SIZE: usize = P::KEY_SIZE;

    fn generate_key() -> Result<SymmetricKey, Error> {
        let mut key_bytes = vec![0u8; P::KEY_SIZE];
        OsRng
            .try_fill_bytes(&mut key_bytes)
            .map_err(|_| Error::Symmetric(SymmetricError::InvalidKeySize))?;
        Ok(SymmetricKey::new(key_bytes))
    }
}

impl<P: AesGcmParams> SymmetricEncryptor for AesGcmScheme<P> {
    fn encrypt(
        key: &Self::Key,
        nonce: &[u8],
        plaintext: &[u8],
        aad: Option<AssociatedData>,
    ) -> Result<Vec<u8>, Error> {
        if key.len() != P::KEY_SIZE {
            return Err(SymmetricError::InvalidKeySize.into());
        }
        if nonce.len() != P::NONCE_SIZE {
            return Err(SymmetricError::InvalidNonceSize.into());
        }
        let key = aes_gcm::Key::<P::AeadCipher>::from_slice(key);
        let cipher = P::AeadCipher::new(key);
        let nonce = NonceCore::from_slice(nonce);

        let payload = Payload {
            msg: plaintext,
            aad: aad.unwrap_or_default(),
        };
        cipher
            .encrypt(nonce, payload)
            .map_err(|_| Error::Symmetric(SymmetricError::Encryption))
    }
}

impl<P: AesGcmParams> SymmetricDecryptor for AesGcmScheme<P> {
    fn decrypt(
        key: &Self::Key,
        nonce: &[u8],
        ciphertext_with_tag: &[u8],
        aad: Option<AssociatedData>,
    ) -> Result<Vec<u8>, Error> {
        if key.len() != P::KEY_SIZE {
            return Err(SymmetricError::InvalidKeySize.into());
        }
        if nonce.len() != P::NONCE_SIZE {
            return Err(SymmetricError::InvalidNonceSize.into());
        }

        let key = aes_gcm::Key::<P::AeadCipher>::from_slice(key);
        let cipher = P::AeadCipher::new(key);
        let nonce = NonceCore::from_slice(nonce);

        let payload = Payload {
            msg: ciphertext_with_tag,
            aad: aad.unwrap_or_default(),
        };
        cipher
            .decrypt(nonce, payload)
            .map_err(|_| Error::Symmetric(SymmetricError::Decryption))
    }
}

// ------------------- Type Aliases -------------------
// ------------------- 类型别名 -------------------

/// A type alias for the AES-128-GCM scheme.
///
/// AES-128-GCM 方案的类型别名。
pub type Aes128Gcm = AesGcmScheme<Aes128GcmParams>;

/// A type alias for the AES-256-GCM scheme.
///
/// AES-256-GCM 方案的类型别名。
pub type Aes256Gcm = AesGcmScheme<Aes256GcmParams>;

/// A type alias for the nonce used in AES-GCM.
///
/// AES-GCM 中使用的 Nonce 的类型别名。
pub type Nonce<'a> = &'a [u8];

/// A type alias for the authentication tag used in AES-GCM.
///
/// AES-GCM 中使用的认证标签的类型别名。
pub type Tag<'a> = &'a [u8];

// ------------------- Tests -------------------
// ------------------- 测试 -------------------

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn test_roundtrip<S>()
    where
        S: SymmetricEncryptor<Key = SymmetricKey>
            + SymmetricDecryptor<Key = SymmetricKey>
            + SymmetricKeyGenerator<Key = Zeroizing<Vec<u8>>>,
    {
        let key = S::generate_key().unwrap();
        let plaintext = b"this is a secret message".to_vec();
        let aad = b"this is authenticated data".to_vec();
        let empty_vec = Vec::new();
        let mut nonce = vec![0u8; S::NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        // With AAD
        // 使用 AAD
        let ciphertext_aad = S::encrypt(&key, &nonce, &plaintext, Some(&aad)).unwrap();
        let decrypted_aad = S::decrypt(&key, &nonce, &ciphertext_aad, Some(&aad)).unwrap();
        assert_eq!(plaintext, decrypted_aad);

        // Without AAD
        // 不使用 AAD
        let ciphertext_no_aad = S::encrypt(&key, &nonce, &plaintext, None).unwrap();
        let decrypted_no_aad = S::decrypt(&key, &nonce, &ciphertext_no_aad, None).unwrap();
        assert_eq!(plaintext, decrypted_no_aad);

        // Empty Plaintext with AAD
        // 空明文和 AAD
        let ciphertext_empty_pt = S::encrypt(&key, &nonce, &empty_vec, Some(&aad)).unwrap();
        let decrypted_empty_pt =
            S::decrypt(&key, &nonce, &ciphertext_empty_pt, Some(&aad)).unwrap();
        assert_eq!(empty_vec, decrypted_empty_pt);

        // Plaintext with Empty AAD
        // 明文和空 AAD
        let ciphertext_empty_aad = S::encrypt(&key, &nonce, &plaintext, Some(&empty_vec)).unwrap();
        let decrypted_empty_aad =
            S::decrypt(&key, &nonce, &ciphertext_empty_aad, Some(&empty_vec)).unwrap();
        assert_eq!(plaintext, decrypted_empty_aad);

        // Empty Plaintext and Empty AAD
        // 空明文和空 AAD
        let ciphertext_all_empty = S::encrypt(&key, &nonce, &empty_vec, Some(&empty_vec)).unwrap();
        let decrypted_all_empty =
            S::decrypt(&key, &nonce, &ciphertext_all_empty, Some(&empty_vec)).unwrap();
        assert_eq!(empty_vec, decrypted_all_empty);

        // Failure cases
        // 失败案例
        let res = S::decrypt(&key, &nonce, &ciphertext_aad, None);
        assert!(matches!(
            res.unwrap_err(),
            Error::Symmetric(SymmetricError::Decryption)
        ));

        let mut tampered_ciphertext = ciphertext_aad.clone();
        tampered_ciphertext[0] ^= 1;
        let res = S::decrypt(&key, &nonce, &tampered_ciphertext, Some(&aad));
        assert!(matches!(
            res.unwrap_err(),
            Error::Symmetric(SymmetricError::Decryption)
        ));

        let mut tampered_aad = aad.clone();
        tampered_aad[0] ^= 1;
        let res = S::decrypt(&key, &nonce, &ciphertext_aad, Some(&tampered_aad));
        assert!(matches!(
            res.unwrap_err(),
            Error::Symmetric(SymmetricError::Decryption)
        ));
    }

    #[test]
    fn test_aes128gcm_scheme() {
        test_roundtrip::<AesGcmScheme<Aes128GcmParams>>();
    }

    #[test]
    fn test_aes256gcm_scheme() {
        test_roundtrip::<AesGcmScheme<Aes256GcmParams>>();
    }

    fn test_invalid_inputs<S>()
    where
        S: SymmetricEncryptor<Key = SymmetricKey>
            + SymmetricDecryptor<Key = SymmetricKey>
            + SymmetricKeyGenerator<Key = SymmetricKey>,
    {
        let key = S::generate_key().unwrap();
        let mut wrong_key = key.clone();
        wrong_key[0] ^= 1;

        let mut nonce = vec![0u8; <S as SymmetricCipher>::NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        let mut wrong_nonce = nonce.clone();
        wrong_nonce[0] ^= 1;

        let plaintext = b"some data";
        let aad = b"some aad";

        let ciphertext = S::encrypt(&key, &nonce, plaintext, Some(aad)).unwrap();

        // Wrong key
        // 错误密钥
        let res = S::decrypt(&wrong_key, &nonce, &ciphertext, Some(aad));
        assert!(matches!(
            res.unwrap_err(),
            Error::Symmetric(SymmetricError::Decryption)
        ));

        // Wrong nonce
        // 错误 Nonce
        let res = S::decrypt(&key, &wrong_nonce, &ciphertext, Some(aad));
        assert!(matches!(
            res.unwrap_err(),
            Error::Symmetric(SymmetricError::Decryption)
        ));

        // Wrong size key
        // 错误大小的密钥
        let wrong_size_key = Zeroizing::new(vec![0; <S as SymmetricCipher>::KEY_SIZE - 1]);
        let res = S::encrypt(&wrong_size_key, &nonce, plaintext, Some(aad));
        assert!(matches!(
            res.unwrap_err(),
            Error::Symmetric(SymmetricError::InvalidKeySize)
        ));

        // Wrong size nonce
        // 错误大小的 Nonce
        let wrong_size_nonce = vec![0; <S as SymmetricCipher>::NONCE_SIZE - 1];
        let res = S::encrypt(&key, &wrong_size_nonce, plaintext, Some(aad));
        assert!(matches!(
            res.unwrap_err(),
            Error::Symmetric(SymmetricError::InvalidNonceSize)
        ));
    }

    #[test]
    fn test_aes128gcm_invalid_inputs() {
        test_invalid_inputs::<AesGcmScheme<Aes128GcmParams>>();
    }

    #[test]
    fn test_aes256gcm_invalid_inputs() {
        test_invalid_inputs::<AesGcmScheme<Aes256GcmParams>>();
    }
}
