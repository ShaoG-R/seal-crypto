//! Provides an implementation of KEM and Signatures using RSA.
//!
//! This module implements RSA-based cryptographic operations including key encapsulation
//! mechanism (KEM) and digital signatures. RSA is a widely-used public-key cryptosystem
//! that provides security based on the difficulty of factoring large integers.
//!
//! # Implemented Schemes
//! - **RSA-OAEP**: Optimal Asymmetric Encryption Padding for KEM functionality
//! - **RSA-PSS**: Probabilistic Signature Scheme for digital signatures
//!
//! # Key Formats
//! Keys are expected to be in PKCS#8 DER format, which is a standard format
//! for storing and transmitting cryptographic keys.
//!
//! # Supported Key Sizes
//! - **RSA-2048**: 2048-bit keys, minimum recommended size for new applications
//! - **RSA-3072**: 3072-bit keys, provides higher security margin
//! - **RSA-4096**: 4096-bit keys, maximum security but slower performance
//!
//! # Security Considerations
//! - RSA security depends on the difficulty of factoring large integers
//! - Vulnerable to quantum computers using Shor's algorithm
//! - Use appropriate padding schemes (OAEP, PSS) to prevent attacks
//! - Key sizes below 2048 bits are considered insecure
//!
//! 提供了使用 RSA 的 KEM 和签名实现。
//!
//! 此模块实现了基于 RSA 的加密操作，包括密钥封装机制 (KEM) 和数字签名。
//! RSA 是一种广泛使用的公钥密码系统，其安全性基于大整数分解的困难性。
//!
//! # 实现的方案
//! - **RSA-OAEP**: 用于 KEM 功能的最优非对称加密填充
//! - **RSA-PSS**: 用于数字签名的概率签名方案
//!
//! # 密钥格式
//! 密钥应为 PKCS#8 DER 格式，这是存储和传输加密密钥的标准格式。
//!
//! # 支持的密钥大小
//! - **RSA-2048**: 2048 位密钥，新应用程序的最小推荐大小
//! - **RSA-3072**: 3072 位密钥，提供更高的安全边际
//! - **RSA-4096**: 4096 位密钥，最大安全性但性能较慢
//!
//! # 安全考虑
//! - RSA 安全性取决于大整数分解的困难性
//! - 容易受到使用 Shor 算法的量子计算机攻击
//! - 使用适当的填充方案（OAEP、PSS）来防止攻击
//! - 低于 2048 位的密钥大小被认为是不安全的

use crate::errors::Error;
use crate::prelude::*;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    rand_core::{OsRng, RngCore},
};
use std::convert::TryFrom;
use std::marker::PhantomData;
use zeroize::{Zeroize, Zeroizing};
// ------------------- Marker Structs and Trait for RSA Parameters -------------------
// ------------------- 用于 RSA 参数的标记结构体和 Trait -------------------

mod private {
    pub trait Sealed {}
}

/// A trait that defines the key size for an RSA scheme.
/// This is a sealed trait, meaning only types within this crate can implement it.
///
/// 一个为 RSA 方案定义密钥大小的 trait。
/// 这是一个密封的 trait，意味着只有此 crate 中的类型才能实现它。
pub trait RsaKeyParams:
    private::Sealed + Send + Sync + 'static + Clone + Default + std::fmt::Debug
{
    /// The number of bits for the RSA key.
    ///
    /// RSA 密钥的位数。
    const KEY_BITS: usize;
    /// The name of the key size.
    ///
    /// 密钥大小的名称。
    const NAME: &'static str;
    /// The base value for the key's ID.
    ///
    /// 密钥ID的基础值。
    const ID_BASE: u32;
}

/// Marker struct for RSA with a 2048-bit key.
///
/// RSA-2048 的标记结构体。
#[derive(Debug, Clone, Default)]
pub struct Rsa2048Params;
impl private::Sealed for Rsa2048Params {}
impl RsaKeyParams for Rsa2048Params {
    const KEY_BITS: usize = 2048;
    const NAME: &'static str = "2048";
    const ID_BASE: u32 = 0x01_01_01_00;
}

/// Marker struct for RSA with a 4096-bit key.
///
/// RSA-4096 的标记结构体。
#[derive(Debug, Clone, Default)]
pub struct Rsa4096Params;
impl private::Sealed for Rsa4096Params {}
impl RsaKeyParams for Rsa4096Params {
    const KEY_BITS: usize = 4096;
    const NAME: &'static str = "4096";
    const ID_BASE: u32 = 0x01_01_01_10;
}

// ------------------- Newtype Wrappers for RSA Keys -------------------
// ------------------- RSA 密钥的 Newtype 包装器 -------------------

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RsaPublicKey(rsa::RsaPublicKey);

impl RsaPublicKey {
    pub fn inner(&self) -> &rsa::RsaPublicKey {
        &self.0
    }
}

#[derive(Debug, Zeroize, Clone, Eq, PartialEq)]
#[zeroize(drop)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RsaPrivateKey(Zeroizing<Vec<u8>>);

impl RsaPrivateKey {
    pub fn inner(&self) -> &[u8] {
        &self.0
    }
}

impl Key for RsaPublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        rsa::RsaPublicKey::from_public_key_der(bytes)
            .map(RsaPublicKey)
            .map_err(|_| KeyError::InvalidEncoding.into())
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.0
            .to_public_key_der()
            .map_err(|_| KeyError::InvalidEncoding)?
            .as_bytes()
            .to_vec())
    }
}
impl PublicKey for RsaPublicKey {}
impl<'a> From<&'a RsaPublicKey> for RsaPublicKey {
    fn from(key: &'a RsaPublicKey) -> Self {
        key.clone()
    }
}

impl TryFrom<&[u8]> for RsaPublicKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Key::from_bytes(bytes)
    }
}

impl Key for RsaPrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        // Just validate that it's a valid key, then store the bytes
        rsa::RsaPrivateKey::from_pkcs8_der(bytes)
            .map_err(|_| Error::Key(KeyError::InvalidEncoding))?;
        Ok(RsaPrivateKey(Zeroizing::new(bytes.to_vec())))
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.0.to_vec())
    }
}

impl TryFrom<&[u8]> for RsaPrivateKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Key::from_bytes(bytes)
    }
}

impl PrivateKey<RsaPublicKey> for RsaPrivateKey {}
// ------------------- Generic RSA Implementation -------------------
// ------------------- 通用 RSA 实现 -------------------

const SHARED_SECRET_SIZE: usize = 32;

/// A generic struct representing the RSA cryptographic scheme.
/// It is generic over the RSA key parameters (key size) and the hash function.
///
/// 一个通用结构体，表示 RSA 密码学方案。
/// 它在 RSA 密钥参数（密钥大小）和哈希函数上是通用的。
#[derive(Clone, Debug, Default)]
pub struct RsaScheme<KP: RsaKeyParams, H: Hasher = Sha256> {
    _key_params: PhantomData<KP>,
    _hasher: PhantomData<H>,
}

impl<KP: RsaKeyParams, H: Hasher + 'static> AsymmetricKeySet for RsaScheme<KP, H> {
    type PublicKey = RsaPublicKey;
    type PrivateKey = RsaPrivateKey;
}

impl<KP: RsaKeyParams, H: Hasher + 'static> Algorithm for RsaScheme<KP, H> {
    fn name() -> String {
        format!("RSA-PSS-{}-{}", KP::NAME, H::NAME)
    }
    const ID: u32 = KP::ID_BASE + H::ID_OFFSET;
}

impl<KP: RsaKeyParams, H: Hasher> Parameterized for RsaScheme<KP, H> {
    fn get_type_params() -> Vec<(&'static str, ParamValue)> {
        vec![
            ("key_params", ParamValue::String(KP::NAME.to_string())),
            ("hash", ParamValue::String(H::NAME.to_string())),
        ]
    }

    fn get_instance_params(&self) -> Vec<(&'static str, ParamValue)> {
        vec![]
    }
}

impl<KP: RsaKeyParams, H: Hasher> KeyGenerator for RsaScheme<KP, H> {
    fn generate_keypair() -> Result<(RsaPublicKey, RsaPrivateKey), Error> {
        let mut rng = OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, KP::KEY_BITS)
            .map_err(|_| Error::Key(KeyError::GenerationFailed))?;
        let public_key = RsaPublicKey(private_key.to_public_key());
        let private_key_der = private_key
            .to_pkcs8_der()
            .map_err(|_| Error::Key(KeyError::InvalidEncoding))?;
        Ok((
            public_key,
            RsaPrivateKey(Zeroizing::new(private_key_der.as_bytes().to_vec())),
        ))
    }
}

impl<KP: RsaKeyParams, H: Hasher> Kem for RsaScheme<KP, H> {
    type EncapsulatedKey = EncapsulatedKey;

    fn encapsulate(public_key: &RsaPublicKey) -> Result<(SharedSecret, EncapsulatedKey), Error> {
        let mut rng = OsRng;
        let mut shared_secret_bytes = vec![0u8; SHARED_SECRET_SIZE];
        rng.fill_bytes(&mut shared_secret_bytes);
        let encapsulated_key = H::rsa_oaep_encrypt(public_key, &shared_secret_bytes)?;
        Ok((Zeroizing::new(shared_secret_bytes), encapsulated_key))
    }

    fn decapsulate(
        private_key: &RsaPrivateKey,
        encapsulated_key: &EncapsulatedKey,
    ) -> Result<SharedSecret, Error> {
        let shared_secret_bytes = H::rsa_oaep_decrypt(private_key, encapsulated_key)?;
        Ok(Zeroizing::new(shared_secret_bytes))
    }
}

impl<KP: RsaKeyParams, H: Hasher> Signer for RsaScheme<KP, H> {
    fn sign(private_key: &RsaPrivateKey, message: &[u8]) -> Result<Signature, Error> {
        H::rsa_pss_sign(private_key, message)
    }
}

impl<KP: RsaKeyParams, H: Hasher> Verifier for RsaScheme<KP, H> {
    fn verify(
        public_key: &RsaPublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), Error> {
        H::rsa_pss_verify(public_key, message, signature)
    }
}

// ------------------- Type Aliases for Specific RSA Schemes -------------------
// ------------------- 特定 RSA 方案的类型别名 -------------------

/// A type alias for the RSA-2048 scheme with SHA-256.
///
/// 使用 SHA-256 的 RSA-2048 方案的类型别名。
pub type Rsa2048<Sha = Sha256> = RsaScheme<Rsa2048Params, Sha>;

/// A type alias for the RSA-4096 scheme with SHA-512.
///
/// 使用 SHA-512 的 RSA-4096 方案的类型别名。
#[cfg(feature = "sha2")]
pub type Rsa4096<Sha = Sha256> = RsaScheme<Rsa4096Params, Sha>;

#[cfg(test)]
mod tests {
    use super::*;

    fn run_rsa_tests<KP: RsaKeyParams, H: Hasher>()
    where
        RsaScheme<KP, H>: KeyGenerator<PublicKey = RsaPublicKey, PrivateKey = RsaPrivateKey>
            + Kem<PublicKey = RsaPublicKey, PrivateKey = RsaPrivateKey>
            + Signer<PrivateKey = RsaPrivateKey>
            + Verifier<PublicKey = RsaPublicKey>,
    {
        // Define the scheme to be tested based on the generic parameters.
        // 根据泛型参数定义要测试的方案。
        type TestScheme<H, KP> = RsaScheme<KP, H>;

        // Test key generation
        // 测试密钥生成
        let (pk, sk) = TestScheme::generate_keypair().unwrap();

        // Test key serialization/deserialization
        // 测试密钥序列化/反序列化
        let pk_bytes = pk.to_bytes().unwrap();
        let sk_bytes = sk.to_bytes().unwrap();
        let pk2 = RsaPublicKey::from_bytes(&pk_bytes).unwrap();
        let sk2 = RsaPrivateKey::from_bytes(&sk_bytes).unwrap();
        assert_eq!(pk.to_bytes(), pk2.to_bytes());
        assert_eq!(sk.to_bytes(), sk2.to_bytes());

        // Test KEM roundtrip
        // 测试 KEM 往返
        let (ss1, encapsulated_key) = TestScheme::encapsulate(&pk).unwrap();
        let ss2 = TestScheme::decapsulate(&sk, &encapsulated_key).unwrap();
        assert_eq!(ss1, ss2);

        // Test sign/verify roundtrip
        // 测试签名/验证往返
        let message = b"this is the message to be signed";
        let signature = TestScheme::sign(&sk, message).unwrap();
        assert!(TestScheme::verify(&pk, message, &signature).is_ok());

        // Test tampered message verification fails
        // 测试篡改消息验证失败
        let tampered_message = b"this is a different message";
        assert!(TestScheme::verify(&pk, tampered_message, &signature).is_err());
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_rsa_2048_sha256() {
        run_rsa_tests::<Rsa2048Params, Sha256>();
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_rsa_4096_sha512() {
        run_rsa_tests::<Rsa4096Params, Sha512>();
    }
}
