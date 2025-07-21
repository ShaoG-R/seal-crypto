//! Hash function parameters and implementations.
//!
//! This module provides concrete implementations of hash functions from the SHA-2 family,
//! along with their associated cryptographic operations like HMAC, PBKDF2, HKDF, and RSA operations.
//!
//! 哈希函数参数和实现。
//!
//! 此模块提供了 SHA-2 系列哈希函数的具体实现，
//! 以及它们相关的加密操作，如 HMAC、PBKDF2、HKDF 和 RSA 操作。

/// Re-exports of `sha2` family hash functions with renamed types to avoid conflicts.
///
/// 重新导出 `sha2` 系列哈希函数，重命名类型以避免冲突。
pub use sha2::{Sha256 as Sha256_, Sha384 as Sha384_, Sha512 as Sha512_};

use crate::{
    errors::Error,
    prelude::PrimitiveParams,
    traits::{
        asymmetric::{KemError, SignatureError},
        kdf::KdfError,
    },
};
#[cfg(feature = "hkdf-default")]
use hkdf::Hkdf;
#[cfg(feature = "rsa-default")]
use {
    rsa::{
        pkcs8::DecodePrivateKey,
        pss::{SigningKey, VerifyingKey},
        Oaep,
        signature::SignatureEncoding,
    },
    crate::systems::asymmetric::traditional::rsa::{RsaPrivateKey, RsaPublicKey},
};
use digest::Digest;
use std::convert::TryFrom;

#[cfg(feature = "hmac-default")]
use crate::prelude::KeyError;

mod private {
    pub trait Sealed {}
}

/// A sealed trait representing a hash function.
/// It provides hashing-related functionalities.
///
/// 一个代表哈希函数的密封 trait。
/// 它提供与哈希相关的功能。
pub trait Hasher: private::Sealed + PrimitiveParams {
    /// Hashes the given data.
    ///
    /// 哈希给定的数据。
    fn hash(data: &[u8]) -> Vec<u8>;

    /// Computes the HMAC of a message using the given key.
    ///
    /// 使用给定的密钥计算消息的 HMAC。
    #[cfg(feature = "hmac-default")]
    fn hmac(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error>;

    /// Derives a key using PBKDF2-HMAC with the hasher.
    ///
    /// # Arguments
    /// * `password` - The password to derive from.
    /// * `salt` - The salt for the derivation.
    /// * `rounds` - The number of iterations.
    /// * `okm` - The output buffer for the derived key material.
    ///
    /// 使用哈希器通过 PBKDF2-HMAC 派生密钥。
    ///
    /// # 参数
    /// * `password` - 要派生的密码。
    /// * `salt` - 派生用的盐。
    /// * `rounds` - 迭代次数。
    /// * `okm` - 派生密钥材料的输出缓冲区。
    #[cfg(feature = "pbkdf2-default")]
    fn pbkdf2_hmac(password: &[u8], salt: &[u8], rounds: u32, okm: &mut [u8]);

    /// Expands a key using HKDF with the hasher.
    ///
    /// # Arguments
    /// * `salt` - Optional salt for the expansion.
    /// * `ikm` - Input keying material.
    /// * `info` - Optional context information.
    /// * `okm` - Output buffer for the expanded key material.
    ///
    /// # Returns
    /// `Ok(())` on success, or a `KdfError` if expansion fails.
    ///
    /// 使用哈希器通过 HKDF 扩展密钥。
    ///
    /// # 参数
    /// * `salt` - 扩展用的可选盐。
    /// * `ikm` - 输入密钥材料。
    /// * `info` - 可选的上下文信息。
    /// * `okm` - 扩展密钥材料的输出缓冲区。
    ///
    /// # 返回
    /// 成功时返回 `Ok(())`，扩展失败时返回 `KdfError`。
    #[cfg(feature = "hkdf-default")]
    fn hkdf_expand(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: Option<&[u8]>,
        okm: &mut [u8],
    ) -> Result<(), KdfError>;

    /// Encrypts data using RSA-OAEP with the hasher.
    ///
    /// # Arguments
    /// * `key` - The RSA public key for encryption.
    /// * `msg` - The message to encrypt.
    ///
    /// # Returns
    /// The encrypted ciphertext, or an error if encryption fails.
    ///
    /// 使用哈希器通过 RSA-OAEP 加密数据。
    ///
    /// # 参数
    /// * `key` - 用于加密的 RSA 公钥。
    /// * `msg` - 要加密的消息。
    ///
    /// # 返回
    /// 加密后的密文，如果加密失败则返回错误。
    #[cfg(feature = "rsa-default")]
    fn rsa_oaep_encrypt(key: &RsaPublicKey, msg: &[u8]) -> Result<Vec<u8>, Error>;

    /// Decrypts data using RSA-OAEP with the hasher.
    ///
    /// # Arguments
    /// * `key` - The RSA private key for decryption.
    /// * `ciphertext` - The ciphertext to decrypt.
    ///
    /// # Returns
    /// The decrypted plaintext, or an error if decryption fails.
    ///
    /// 使用哈希器通过 RSA-OAEP 解密数据。
    ///
    /// # 参数
    /// * `key` - 用于解密的 RSA 私钥。
    /// * `ciphertext` - 要解密的密文。
    ///
    /// # 返回
    /// 解密后的明文，如果解密失败则返回错误。
    #[cfg(feature = "rsa-default")]
    fn rsa_oaep_decrypt(key: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error>;

    /// Signs a message using RSA-PSS with the hasher.
    ///
    /// # Arguments
    /// * `key` - The RSA private key for signing.
    /// * `msg` - The message to sign.
    ///
    /// # Returns
    /// The signature bytes, or an error if signing fails.
    ///
    /// 使用哈希器通过 RSA-PSS 签名消息。
    ///
    /// # 参数
    /// * `key` - 用于签名的 RSA 私钥。
    /// * `msg` - 要签名的消息。
    ///
    /// # 返回
    /// 签名字节，如果签名失败则返回错误。
    #[cfg(feature = "rsa-default")]
    fn rsa_pss_sign(key: &RsaPrivateKey, msg: &[u8]) -> Result<Vec<u8>, Error>;

    /// Verifies a signature using RSA-PSS with the hasher.
    ///
    /// # Arguments
    /// * `key` - The RSA public key for verification.
    /// * `msg` - The original message.
    /// * `sig` - The signature to verify.
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid, or an error if verification fails.
    ///
    /// 使用哈希器通过 RSA-PSS 验证签名。
    ///
    /// # 参数
    /// * `key` - 用于验证的 RSA 公钥。
    /// * `msg` - 原始消息。
    /// * `sig` - 要验证的签名。
    ///
    /// # 返回
    /// 如果签名有效则返回 `Ok(())`，验证失败则返回错误。
    #[cfg(feature = "rsa-default")]
    fn rsa_pss_verify(key: &RsaPublicKey, msg: &[u8], sig: &[u8]) -> Result<(), Error>;
}

/// SHA-256 hash function implementation.
///
/// This struct provides a concrete implementation of the SHA-256 cryptographic hash function
/// and its associated operations like HMAC, PBKDF2, HKDF, and RSA operations.
///
/// SHA-256 哈希函数实现。
///
/// 此结构体提供了 SHA-256 加密哈希函数及其相关操作（如 HMAC、PBKDF2、HKDF 和 RSA 操作）的具体实现。
#[derive(Clone, Default, Debug)]
pub struct Sha256;

impl private::Sealed for Sha256 {}

impl PrimitiveParams for Sha256 {
    const NAME: &'static str = "SHA-256";
    const ID_OFFSET: u32 = 1;
}

impl Hasher for Sha256 {
    fn hash(data: &[u8]) -> Vec<u8> {
        Sha256_::digest(data).to_vec()
    }

    #[cfg(feature = "hmac-default")]
    fn hmac(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        use hmac::{Hmac, Mac};

        let mut mac = Hmac::<Sha256_>::new_from_slice(key).map_err(|_| KeyError::InvalidLength)?;
        mac.update(msg);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    #[cfg(feature = "pbkdf2-default")]
    fn pbkdf2_hmac(password: &[u8], salt: &[u8], rounds: u32, okm: &mut [u8]) {
        pbkdf2::pbkdf2_hmac::<Sha256_>(password, salt, rounds, okm);
    }

    #[cfg(feature = "hkdf-default")]
    fn hkdf_expand(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: Option<&[u8]>,
        okm: &mut [u8],
    ) -> Result<(), KdfError> {
        let hk = Hkdf::<Sha256_>::new(salt, ikm);
        hk.expand(info.unwrap_or_default(), okm)
            .map_err(|_| KdfError::InvalidOutputLength)
    }

    #[cfg(feature = "rsa-default")]
    fn rsa_oaep_encrypt(key: &RsaPublicKey, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let padding = Oaep::new::<Sha256_>();
        key.inner()
            .encrypt(&mut rsa::rand_core::OsRng, padding, msg)
            .map_err(|_| KemError::Encapsulation.into())
    }

    #[cfg(feature = "rsa-default")]
    fn rsa_oaep_decrypt(key: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let rsa_private_key = rsa::RsaPrivateKey::from_pkcs8_der(key.inner())
            .map_err(|_| KemError::InvalidPrivateKey)?;
        let padding = Oaep::new::<Sha256_>();
        rsa_private_key
            .decrypt(padding, ciphertext)
            .map_err(|_| KemError::Decapsulation.into())
    }

    #[cfg(feature = "rsa-default")]
    fn rsa_pss_sign(key: &RsaPrivateKey, msg: &[u8]) -> Result<Vec<u8>, Error> {
        use rsa::signature::RandomizedSigner;
        let rsa_private_key = rsa::RsaPrivateKey::from_pkcs8_der(key.inner())
            .map_err(|_| Error::Signature(SignatureError::Signing))?;
        let signing_key = SigningKey::<Sha256_>::new(rsa_private_key);
        let mut rng = rsa::rand_core::OsRng;
        let signature = signing_key.sign_with_rng(&mut rng, msg);
        Ok(signature.to_vec())
    }

    #[cfg(feature = "rsa-default")]
    fn rsa_pss_verify(key: &RsaPublicKey, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        use rsa::signature::Verifier;
        let verifying_key = VerifyingKey::<Sha256_>::new(key.inner().clone());
        let pss_signature = rsa::pss::Signature::try_from(sig)
            .map_err(|_| SignatureError::InvalidSignature)?;
        verifying_key
            .verify(msg, &pss_signature)
            .map_err(|_| SignatureError::Verification.into())
    }
}

/// SHA-384 hash function implementation.
///
/// This struct provides a concrete implementation of the SHA-384 cryptographic hash function
/// and its associated operations like HMAC, PBKDF2, HKDF, and RSA operations.
///
/// SHA-384 哈希函数实现。
///
/// 此结构体提供了 SHA-384 加密哈希函数及其相关操作（如 HMAC、PBKDF2、HKDF 和 RSA 操作）的具体实现。
#[derive(Clone, Default, Debug)]
pub struct Sha384;

impl private::Sealed for Sha384 {}

impl PrimitiveParams for Sha384 {
    const NAME: &'static str = "SHA-384";
    const ID_OFFSET: u32 = 2;
}

impl Hasher for Sha384 {
    fn hash(data: &[u8]) -> Vec<u8> {
        Sha384_::digest(data).to_vec()
    }

    #[cfg(feature = "hmac-default")]
    fn hmac(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<Sha384_>::new_from_slice(key).map_err(|_| KeyError::InvalidLength)?;
        mac.update(msg);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    #[cfg(feature = "pbkdf2-default")]
    fn pbkdf2_hmac(password: &[u8], salt: &[u8], rounds: u32, okm: &mut [u8]) {
        pbkdf2::pbkdf2_hmac::<Sha384_>(password, salt, rounds, okm);
    }

    #[cfg(feature = "hkdf-default")]
    fn hkdf_expand(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: Option<&[u8]>,
        okm: &mut [u8],
    ) -> Result<(), KdfError> {
        let hk = Hkdf::<Sha384_>::new(salt, ikm);
        hk.expand(info.unwrap_or_default(), okm)
            .map_err(|_| KdfError::InvalidOutputLength)
    }

    #[cfg(feature = "rsa-default")]
    fn rsa_oaep_encrypt(key: &RsaPublicKey, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let padding = Oaep::new::<Sha384_>();
        key.inner()
            .encrypt(&mut rsa::rand_core::OsRng, padding, msg)
            .map_err(|_| KemError::Encapsulation.into())
    }

    #[cfg(feature = "rsa-default")]
    fn rsa_oaep_decrypt(key: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let rsa_private_key = rsa::RsaPrivateKey::from_pkcs8_der(key.inner())
            .map_err(|_| KemError::InvalidPrivateKey)?;
        let padding = Oaep::new::<Sha384_>();
        rsa_private_key
            .decrypt(padding, ciphertext)
            .map_err(|_| KemError::Decapsulation.into())
    }

    #[cfg(feature = "rsa-default")]
    fn rsa_pss_sign(key: &RsaPrivateKey, msg: &[u8]) -> Result<Vec<u8>, Error> {
        use rsa::signature::RandomizedSigner;
        let rsa_private_key = rsa::RsaPrivateKey::from_pkcs8_der(key.inner())
            .map_err(|_| Error::Signature(SignatureError::Signing))?;
        let signing_key = SigningKey::<Sha384_>::new(rsa_private_key);
        let mut rng = rsa::rand_core::OsRng;
        let signature = signing_key.sign_with_rng(&mut rng, msg);
        Ok(signature.to_vec())
    }

    #[cfg(feature = "rsa-default")]
    fn rsa_pss_verify(key: &RsaPublicKey, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        use rsa::signature::Verifier;
        let verifying_key = VerifyingKey::<Sha384_>::new(key.inner().clone());
        let pss_signature = rsa::pss::Signature::try_from(sig)
            .map_err(|_| SignatureError::InvalidSignature)?;
        verifying_key
            .verify(msg, &pss_signature)
            .map_err(|_| SignatureError::Verification.into())
    }
}

/// SHA-512 hash function implementation.
///
/// This struct provides a concrete implementation of the SHA-512 cryptographic hash function
/// and its associated operations like HMAC, PBKDF2, HKDF, and RSA operations.
///
/// SHA-512 哈希函数实现。
///
/// 此结构体提供了 SHA-512 加密哈希函数及其相关操作（如 HMAC、PBKDF2、HKDF 和 RSA 操作）的具体实现。
#[derive(Clone, Default, Debug)]
pub struct Sha512;

impl private::Sealed for Sha512 {}

impl PrimitiveParams for Sha512 {
    const NAME: &'static str = "SHA-512";
    const ID_OFFSET: u32 = 3;
}

impl Hasher for Sha512 {
    fn hash(data: &[u8]) -> Vec<u8> {
        Sha512_::digest(data).to_vec()
    }

    #[cfg(feature = "hmac-default")]
    fn hmac(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<Sha512_>::new_from_slice(key).map_err(|_| KeyError::InvalidLength)?;
        mac.update(msg);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    #[cfg(feature = "pbkdf2-default")]
    fn pbkdf2_hmac(password: &[u8], salt: &[u8], rounds: u32, okm: &mut [u8]) {
        pbkdf2::pbkdf2_hmac::<Sha512_>(password, salt, rounds, okm);
    }

    #[cfg(feature = "hkdf-default")]
    fn hkdf_expand(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: Option<&[u8]>,
        okm: &mut [u8],
    ) -> Result<(), KdfError> {
        let hk = Hkdf::<Sha512_>::new(salt, ikm);
        hk.expand(info.unwrap_or_default(), okm)
            .map_err(|_| KdfError::InvalidOutputLength)
    }

    #[cfg(feature = "rsa-default")]
    fn rsa_oaep_encrypt(key: &RsaPublicKey, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let padding = Oaep::new::<Sha512_>();
        key.inner()
            .encrypt(&mut rsa::rand_core::OsRng, padding, msg)
            .map_err(|_| KemError::Encapsulation.into())
    }

    #[cfg(feature = "rsa-default")]
    fn rsa_oaep_decrypt(key: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let rsa_private_key = rsa::RsaPrivateKey::from_pkcs8_der(key.inner())
            .map_err(|_| KemError::InvalidPrivateKey)?;
        let padding = Oaep::new::<Sha512_>();
        rsa_private_key
            .decrypt(padding, ciphertext)
            .map_err(|_| KemError::Decapsulation.into())
    }

    #[cfg(feature = "rsa-default")]
    fn rsa_pss_sign(key: &RsaPrivateKey, msg: &[u8]) -> Result<Vec<u8>, Error> {
        use rsa::signature::RandomizedSigner;
        let rsa_private_key = rsa::RsaPrivateKey::from_pkcs8_der(key.inner())
            .map_err(|_| Error::Signature(SignatureError::Signing))?;
        let signing_key = SigningKey::<Sha512_>::new(rsa_private_key);
        let mut rng = rsa::rand_core::OsRng;
        let signature = signing_key.sign_with_rng(&mut rng, msg);
        Ok(signature.to_vec())
    }

    #[cfg(feature = "rsa-default")]
    fn rsa_pss_verify(key: &RsaPublicKey, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        use rsa::signature::Verifier;
        let verifying_key = VerifyingKey::<Sha512_>::new(key.inner().clone());
        let pss_signature = rsa::pss::Signature::try_from(sig)
            .map_err(|_| SignatureError::InvalidSignature)?;
        verifying_key
            .verify(msg, &pss_signature)
            .map_err(|_| SignatureError::Verification.into())
    }
}