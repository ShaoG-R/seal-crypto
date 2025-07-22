//! Provides an implementation of symmetric authenticated encryption (AEAD) using AES-GCM.
//!
//! This module implements the Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM),
//! which provides authenticated encryption with associated data (AEAD). AES-GCM is widely
//! used and standardized, offering excellent performance on hardware with AES acceleration.
//!
//! # Supported Key Sizes
//! - **AES-128-GCM**: 128-bit keys, suitable for most applications
//! - **AES-256-GCM**: 256-bit keys, provides higher security margin
//!
//! # Security Features
//! - Authenticated encryption: provides both confidentiality and authenticity
//! - Associated data authentication: can authenticate additional data without encrypting it
//! - Nonce-based: requires unique nonces for each encryption operation
//!
//! # Performance Considerations
//! - Hardware acceleration available on most modern processors
//! - Constant-time implementation resistant to timing attacks
//! - Efficient for both small and large data sizes
//!
//! 提供了使用 AES-GCM 的对称认证加密（AEAD）实现。
//!
//! 此模块实现了伽罗瓦/计数器模式 (GCM) 的高级加密标准 (AES)，
//! 它提供带关联数据的认证加密 (AEAD)。AES-GCM 被广泛使用和标准化，
//! 在具有 AES 加速的硬件上提供出色的性能。
//!
//! # 支持的密钥大小
//! - **AES-128-GCM**: 128 位密钥，适用于大多数应用
//! - **AES-256-GCM**: 256 位密钥，提供更高的安全边际
//!
//! # 安全特性
//! - 认证加密：同时提供机密性和真实性
//! - 关联数据认证：可以在不加密的情况下认证额外数据
//! - 基于 nonce：每次加密操作都需要唯一的 nonce
//!
//! # 性能考虑
//! - 在大多数现代处理器上可用硬件加速
//! - 恒定时间实现，抵抗时序攻击
//! - 对小型和大型数据都高效

use crate::errors::Error;
use crate::prelude::*;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, AeadInPlace, KeyInit, OsRng};
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
pub trait AesGcmParams: private::Sealed + SchemeParams {
    /// The underlying `aes_gcm` AEAD cipher type.
    ///
    /// 底层的 `aes_gcm` AEAD 密码类型。
    type AeadCipher: Aead + AeadInPlace + KeyInit;
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

/// Marker struct for AES-128-GCM parameters.
///
/// This struct defines the parameters for AES-128-GCM, which uses 128-bit keys
/// and provides a good balance between security and performance for most applications.
///
/// AES-128-GCM 参数的标记结构体。
///
/// 此结构体定义了 AES-128-GCM 的参数，它使用 128 位密钥，
/// 为大多数应用程序在安全性和性能之间提供了良好的平衡。
#[derive(Clone, Debug, Default)]
pub struct Aes128GcmParams;
impl private::Sealed for Aes128GcmParams {}
impl SchemeParams for Aes128GcmParams {
    const NAME: &'static str = "AES-128-GCM";
    const ID: u32 = 0x02_01_01_01;
}
impl AesGcmParams for Aes128GcmParams {
    type AeadCipher = Aes128GcmCore;
    const KEY_SIZE: usize = 16;
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;
}

/// Marker struct for AES-256-GCM parameters.
///
/// This struct defines the parameters for AES-256-GCM, which uses 256-bit keys
/// and provides a higher security margin suitable for long-term protection
/// and high-security applications.
///
/// AES-256-GCM 参数的标记结构体。
///
/// 此结构体定义了 AES-256-GCM 的参数，它使用 256 位密钥，
/// 提供更高的安全边际，适用于长期保护和高安全性应用。
#[derive(Clone, Debug, Default)]
pub struct Aes256GcmParams;
impl private::Sealed for Aes256GcmParams {}
impl SchemeParams for Aes256GcmParams {
    const NAME: &'static str = "AES-256-GCM";
    const ID: u32 = 0x02_01_01_02;
}
impl AesGcmParams for Aes256GcmParams {
    type AeadCipher = Aes256GcmCore;
    const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;
}

// ------------------- Generic AES-GCM Implementation -------------------
// ------------------- 通用 AES-GCM 实现 -------------------

/// A generic struct representing the AES-GCM cryptographic system for a given parameter set.
///
/// This struct implements the complete AES-GCM AEAD scheme, providing key generation,
/// encryption, and decryption capabilities. It is parameterized over different AES-GCM
/// configurations (e.g., AES-128-GCM, AES-256-GCM) to allow compile-time selection
/// of the desired security level and performance characteristics.
///
/// # Type Parameters
/// * `P` - The parameter set defining key size, nonce size, and tag size
///
/// # Security Guarantees
/// - Provides authenticated encryption with associated data (AEAD)
/// - Resistant to chosen-plaintext and chosen-ciphertext attacks
/// - Constant-time implementation prevents timing attacks
///
/// 一个通用结构体，表示给定参数集的 AES-GCM 密码系统。
///
/// 此结构体实现了完整的 AES-GCM AEAD 方案，提供密钥生成、加密和解密功能。
/// 它在不同的 AES-GCM 配置（例如 AES-128-GCM、AES-256-GCM）上参数化，
/// 以允许编译时选择所需的安全级别和性能特征。
///
/// # 类型参数
/// * `P` - 定义密钥大小、nonce 大小和标签大小的参数集
///
/// # 安全保证
/// - 提供带关联数据的认证加密 (AEAD)
/// - 抵抗选择明文和选择密文攻击
/// - 恒定时间实现防止时序攻击
#[derive(Clone, Debug, Default)]
pub struct AesGcmScheme<P: AesGcmParams> {
    _params: PhantomData<P>,
}

impl<P: AesGcmParams> Algorithm for AesGcmScheme<P> {
    fn name() -> String {
        P::NAME.to_string()
    }
    const ID: u32 = P::ID;
}

impl<P: AesGcmParams> SymmetricKeySet for AesGcmScheme<P> {
    type Key = SymmetricKey;
}

impl<P: AesGcmParams> AeadCipher for AesGcmScheme<P> {
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
            .map_err(|_| Error::Key(KeyError::GenerationFailed))?;
        Ok(SymmetricKey::new(key_bytes))
    }
}

impl<P: AesGcmParams> AeadEncryptor for AesGcmScheme<P> {
    fn encrypt_to_buffer(
        key: &Self::Key,
        nonce: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
        aad: Option<AssociatedData>,
    ) -> Result<usize, Error> {
        if key.len() != P::KEY_SIZE {
            return Err(Error::Symmetric(SymmetricError::InvalidKeySize));
        }
        if nonce.len() != P::NONCE_SIZE {
            return Err(Error::Symmetric(SymmetricError::InvalidNonceSize));
        }

        let required_len = plaintext.len() + P::TAG_SIZE;
        if output.len() < required_len {
            return Err(Error::Symmetric(SymmetricError::OutputTooSmall));
        }

        let key = aes_gcm::Key::<P::AeadCipher>::from_slice(key);
        let cipher = P::AeadCipher::new(key);
        let nonce = NonceCore::from_slice(nonce);

        let (ciphertext_buf, tag_buf) = output.split_at_mut(plaintext.len());
        ciphertext_buf.copy_from_slice(plaintext);

        let tag = cipher
            .encrypt_in_place_detached(nonce, aad.unwrap_or_default(), ciphertext_buf)
            .map_err(|_| Error::Symmetric(SymmetricError::Encryption))?;

        tag_buf[..P::TAG_SIZE].copy_from_slice(&tag);

        Ok(required_len)
    }
}

impl<P: AesGcmParams> AeadDecryptor for AesGcmScheme<P> {
    fn decrypt_to_buffer(
        key: &Self::Key,
        nonce: &[u8],
        ciphertext_with_tag: &[u8],
        output: &mut [u8],
        aad: Option<AssociatedData>,
    ) -> Result<usize, Error> {
        if key.len() != P::KEY_SIZE {
            return Err(Error::Symmetric(SymmetricError::InvalidKeySize));
        }
        if nonce.len() != P::NONCE_SIZE {
            return Err(Error::Symmetric(SymmetricError::InvalidNonceSize));
        }
        if ciphertext_with_tag.len() < P::TAG_SIZE {
            return Err(Error::Symmetric(SymmetricError::InvalidCiphertext));
        }

        let (ciphertext, tag) =
            ciphertext_with_tag.split_at(ciphertext_with_tag.len() - P::TAG_SIZE);

        if output.len() < ciphertext.len() {
            return Err(Error::Symmetric(SymmetricError::OutputTooSmall));
        }

        let key = aes_gcm::Key::<P::AeadCipher>::from_slice(key);
        let cipher = P::AeadCipher::new(key);
        let nonce = NonceCore::from_slice(nonce);
        let tag = aes_gcm::Tag::from_slice(tag);

        let plaintext_buf = &mut output[..ciphertext.len()];
        plaintext_buf.copy_from_slice(ciphertext);

        cipher
            .decrypt_in_place_detached(nonce, aad.unwrap_or_default(), plaintext_buf, tag)
            .map_err(|_| Error::Symmetric(SymmetricError::Decryption))?;

        Ok(plaintext_buf.len())
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
        S: AeadEncryptor<Key = SymmetricKey>
            + AeadDecryptor<Key = SymmetricKey>
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

        // Test buffer encryption with AAD
        let mut encrypted_buffer_aad = vec![0u8; plaintext.len() + S::TAG_SIZE];
        let bytes_written = S::encrypt_to_buffer(
            &key,
            &nonce,
            &plaintext,
            &mut encrypted_buffer_aad,
            Some(&aad),
        )
        .unwrap();
        assert_eq!(bytes_written, ciphertext_aad.len());
        assert_eq!(ciphertext_aad, &encrypted_buffer_aad[..bytes_written]);

        let mut decrypted_buffer_aad = vec![0u8; plaintext.len()];
        let bytes_written = S::decrypt_to_buffer(
            &key,
            &nonce,
            &encrypted_buffer_aad,
            &mut decrypted_buffer_aad,
            Some(&aad),
        )
        .unwrap();
        assert_eq!(bytes_written, plaintext.len());
        assert_eq!(plaintext, &decrypted_buffer_aad[..bytes_written]);

        // Without AAD
        // 不使用 AAD
        let ciphertext_no_aad = S::encrypt(&key, &nonce, &plaintext, None).unwrap();
        let decrypted_no_aad = S::decrypt(&key, &nonce, &ciphertext_no_aad, None).unwrap();
        assert_eq!(plaintext, decrypted_no_aad);

        // Test buffer encryption without AAD
        let mut encrypted_buffer_no_aad = vec![0u8; plaintext.len() + S::TAG_SIZE];
        let bytes_written =
            S::encrypt_to_buffer(&key, &nonce, &plaintext, &mut encrypted_buffer_no_aad, None)
                .unwrap();
        assert_eq!(bytes_written, ciphertext_no_aad.len());
        assert_eq!(ciphertext_no_aad, &encrypted_buffer_no_aad[..bytes_written]);

        let mut decrypted_buffer_no_aad = vec![0u8; plaintext.len()];
        let bytes_written = S::decrypt_to_buffer(
            &key,
            &nonce,
            &encrypted_buffer_no_aad,
            &mut decrypted_buffer_no_aad,
            None,
        )
        .unwrap();
        assert_eq!(bytes_written, plaintext.len());
        assert_eq!(plaintext, &decrypted_buffer_no_aad[..bytes_written]);

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
        S: AeadEncryptor<Key = SymmetricKey>
            + AeadDecryptor<Key = SymmetricKey>
            + SymmetricKeyGenerator<Key = SymmetricKey>,
    {
        let key = S::generate_key().unwrap();
        let mut wrong_key = key.clone();
        wrong_key[0] ^= 1;

        let mut nonce = vec![0u8; <S as AeadCipher>::NONCE_SIZE];
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
        let wrong_size_key = Zeroizing::new(vec![0; <S as AeadCipher>::KEY_SIZE - 1]);
        let res = S::encrypt(&wrong_size_key, &nonce, plaintext, Some(aad));
        assert!(matches!(
            res.unwrap_err(),
            Error::Symmetric(SymmetricError::InvalidKeySize)
        ));

        // Wrong size nonce
        // 错误大小的 Nonce
        let wrong_size_nonce = vec![0; <S as AeadCipher>::NONCE_SIZE - 1];
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
