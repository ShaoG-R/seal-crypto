//! Provides an implementation of the Dilithium post-quantum signature scheme.
//!
//! Dilithium is a digital signature scheme that is designed to be secure against attacks
//! by both classical and quantum computers. It is based on the hardness of lattice problems,
//! specifically the Module Learning With Errors (Module-LWE) and Module Short Integer
//! Solution (Module-SIS) problems. Dilithium was selected by NIST for standardization
//! in the post-quantum cryptography competition.
//!
//! # Algorithm Variants
//! - **Dilithium2**: Provides security equivalent to AES-128, smallest signatures
//! - **Dilithium3**: Provides security equivalent to AES-192, balanced security/performance
//! - **Dilithium5**: Provides security equivalent to AES-256, highest security
//!
//! # Security Properties
//! - Resistant to quantum computer attacks using Shor's and Grover's algorithms
//! - Based on well-studied lattice problems (Module-LWE, Module-SIS)
//! - Provides strong unforgeability under chosen message attacks (SUF-CMA)
//! - Deterministic signatures for the same message and key
//! - Constant-time implementation resistant to side-channel attacks
//!
//! # Performance Characteristics
//! - Fast signature generation and verification
//! - Moderate signature sizes compared to other post-quantum schemes
//! - Efficient implementation suitable for both software and hardware
//! - Good performance scaling across different security levels
//!
//! # Signature Sizes (approximate)
//! - **Dilithium2**: ~2,420 bytes
//! - **Dilithium3**: ~3,293 bytes
//! - **Dilithium5**: ~4,595 bytes
//!
//! # Key Sizes (approximate)
//! - **Dilithium2**: Public key ~1,312 bytes, Private key ~2,528 bytes
//! - **Dilithium3**: Public key ~1,952 bytes, Private key ~4,000 bytes
//! - **Dilithium5**: Public key ~2,592 bytes, Private key ~4,864 bytes
//!
//! # Use Cases
//! - Long-term digital signatures requiring quantum resistance
//! - Certificate authorities transitioning to post-quantum cryptography
//! - Government and military applications with high security requirements
//! - Hybrid classical/post-quantum systems during transition period
//! - Applications requiring future-proof digital signatures
//!
//! # Security Considerations
//! - Choose appropriate security level based on threat model
//! - Consider signature size constraints in bandwidth-limited applications
//! - Use secure random number generation for key generation
//! - Protect private keys with appropriate access controls
//! - Consider hybrid schemes during transition period
//!
//! # Standardization Status
//! Dilithium is being standardized by NIST as part of the post-quantum cryptography
//! standardization process. It is recommended for new applications requiring
//! quantum-resistant digital signatures.
//!
//! 提供了 Dilithium 后量子签名方案的实现。
//!
//! Dilithium 是一种数字签名方案，设计为能够抵抗经典和量子计算机的攻击。
//! 它基于格问题的困难性，特别是模块学习与错误 (Module-LWE) 和模块短整数解
//! (Module-SIS) 问题。Dilithium 被 NIST 选择在后量子密码学竞赛中进行标准化。
//!
//! # 算法变体
//! - **Dilithium2**: 提供相当于 AES-128 的安全性，最小的签名
//! - **Dilithium3**: 提供相当于 AES-192 的安全性，平衡安全性/性能
//! - **Dilithium5**: 提供相当于 AES-256 的安全性，最高安全性
//!
//! # 安全属性
//! - 抵抗使用 Shor 和 Grover 算法的量子计算机攻击
//! - 基于经过充分研究的格问题 (Module-LWE, Module-SIS)
//! - 在选择消息攻击下提供强不可伪造性 (SUF-CMA)
//! - 对相同消息和密钥的确定性签名
//! - 恒定时间实现，抵抗侧信道攻击
//!
//! # 性能特征
//! - 快速的签名生成和验证
//! - 与其他后量子方案相比，签名大小适中
//! - 适用于软件和硬件的高效实现
//! - 在不同安全级别上良好的性能扩展
//!
//! # 签名大小（近似）
//! - **Dilithium2**: ~2,420 字节
//! - **Dilithium3**: ~3,293 字节
//! - **Dilithium5**: ~4,595 字节
//!
//! # 密钥大小（近似）
//! - **Dilithium2**: 公钥 ~1,312 字节，私钥 ~2,528 字节
//! - **Dilithium3**: 公钥 ~1,952 字节，私钥 ~4,000 字节
//! - **Dilithium5**: 公钥 ~2,592 字节，私钥 ~4,864 字节
//!
//! # 使用场景
//! - 需要抗量子性的长期数字签名
//! - 过渡到后量子密码学的证书颁发机构
//! - 具有高安全要求的政府和军事应用
//! - 过渡期间的混合经典/后量子系统
//! - 需要面向未来的数字签名的应用程序
//!
//! # 安全考虑
//! - 根据威胁模型选择适当的安全级别
//! - 在带宽受限的应用中考虑签名大小约束
//! - 为密钥生成使用安全的随机数生成
//! - 使用适当的访问控制保护私钥
//! - 在过渡期间考虑混合方案
//!
//! # 标准化状态
//! Dilithium 正在被 NIST 作为后量子密码学标准化过程的一部分进行标准化。
//! 推荐用于需要抗量子数字签名的新应用程序。

use crate::errors::Error;
use crate::prelude::*;
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use pqcrypto_traits::sign::{
    DetachedSignature as PqDetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use std::convert::TryFrom;
use std::marker::PhantomData;
use zeroize::{Zeroize, Zeroizing};

// ------------------- Marker Structs and Trait for Dilithium Parameters -------------------
// ------------------- 用于 Dilithium 参数的标记结构体和 Trait -------------------

mod private {
    pub trait Sealed {}
}

/// A trait that defines the parameters for a specific Dilithium security level.
/// This is a sealed trait, meaning only types within this crate can implement it.
///
/// 一个定义特定 Dilithium 安全级别参数的 trait。
/// 这是一个密封的 trait，意味着只有此 crate 中的类型才能实现它。
pub trait DilithiumParams: private::Sealed + SchemeParams {
    type PqPublicKey: PqPublicKey + Clone;
    type PqSecretKey: PqSecretKey + Clone;
    type PqDetachedSignature: PqDetachedSignature;

    fn public_key_bytes() -> usize;
    fn secret_key_bytes() -> usize;

    fn keypair() -> (Self::PqPublicKey, Self::PqSecretKey);
    fn sign(sk: &Self::PqSecretKey, msg: &[u8]) -> Self::PqDetachedSignature;
    fn verify(
        sig: &Self::PqDetachedSignature,
        msg: &[u8],
        pk: &Self::PqPublicKey,
    ) -> Result<(), Error>;
}

/// Marker struct for Dilithium2 parameters.
///
/// Dilithium2 provides the smallest signature size and fastest performance
/// while maintaining security equivalent to AES-128. It is suitable for
/// applications where signature size and speed are critical.
///
/// Dilithium2 参数的标记结构体。
///
/// Dilithium2 提供最小的签名大小和最快的性能，
/// 同时保持相当于 AES-128 的安全性。它适用于签名大小和速度至关重要的应用程序。
#[derive(Debug, Default, Clone)]
pub struct Dilithium2Params;
impl private::Sealed for Dilithium2Params {}
impl SchemeParams for Dilithium2Params {
    const NAME: &'static str = "Dilithium2";
    const ID: u32 = 0x01_02_01_02;
}
impl DilithiumParams for Dilithium2Params {
    type PqPublicKey = dilithium2::PublicKey;
    type PqSecretKey = dilithium2::SecretKey;
    type PqDetachedSignature = dilithium2::DetachedSignature;

    fn public_key_bytes() -> usize {
        dilithium2::public_key_bytes()
    }
    fn secret_key_bytes() -> usize {
        dilithium2::secret_key_bytes()
    }

    fn keypair() -> (Self::PqPublicKey, Self::PqSecretKey) {
        dilithium2::keypair()
    }
    fn sign(sk: &Self::PqSecretKey, msg: &[u8]) -> Self::PqDetachedSignature {
        dilithium2::detached_sign(msg, sk)
    }
    fn verify(
        sig: &Self::PqDetachedSignature,
        msg: &[u8],
        pk: &Self::PqPublicKey,
    ) -> Result<(), Error> {
        dilithium2::verify_detached_signature(sig, msg, pk)
            .map_err(|_| Error::Signature(SignatureError::Verification))
    }
}

/// Marker struct for Dilithium3 parameters.
///
/// Dilithium3 provides a balanced trade-off between security, signature size,
/// and performance. It offers security equivalent to AES-192 and is recommended
/// for most applications requiring post-quantum digital signatures.
///
/// Dilithium3 参数的标记结构体。
///
/// Dilithium3 在安全性、签名大小和性能之间提供平衡的权衡。
/// 它提供相当于 AES-192 的安全性，推荐用于大多数需要后量子数字签名的应用程序。
#[derive(Debug, Default, Clone)]
pub struct Dilithium3Params;
impl private::Sealed for Dilithium3Params {}
impl SchemeParams for Dilithium3Params {
    const NAME: &'static str = "Dilithium3";
    const ID: u32 = 0x01_02_01_03;
}
impl DilithiumParams for Dilithium3Params {
    type PqPublicKey = dilithium3::PublicKey;
    type PqSecretKey = dilithium3::SecretKey;
    type PqDetachedSignature = dilithium3::DetachedSignature;

    fn public_key_bytes() -> usize {
        dilithium3::public_key_bytes()
    }
    fn secret_key_bytes() -> usize {
        dilithium3::secret_key_bytes()
    }

    fn keypair() -> (Self::PqPublicKey, Self::PqSecretKey) {
        dilithium3::keypair()
    }
    fn sign(sk: &Self::PqSecretKey, msg: &[u8]) -> Self::PqDetachedSignature {
        dilithium3::detached_sign(msg, sk)
    }
    fn verify(
        sig: &Self::PqDetachedSignature,
        msg: &[u8],
        pk: &Self::PqPublicKey,
    ) -> Result<(), Error> {
        dilithium3::verify_detached_signature(sig, msg, pk)
            .map_err(|_| Error::Signature(SignatureError::Verification))
    }
}

/// Marker struct for Dilithium5 parameters.
///
/// Dilithium5 provides the highest security level equivalent to AES-256,
/// suitable for applications with the most stringent security requirements.
/// It has larger signature sizes and slower performance compared to other variants.
///
/// Dilithium5 参数的标记结构体。
///
/// Dilithium5 提供相当于 AES-256 的最高安全级别，
/// 适用于具有最严格安全要求的应用程序。
/// 与其他变体相比，它具有更大的签名大小和更慢的性能。
#[derive(Debug, Default, Clone)]
pub struct Dilithium5Params;
impl private::Sealed for Dilithium5Params {}
impl SchemeParams for Dilithium5Params {
    const NAME: &'static str = "Dilithium5";
    const ID: u32 = 0x01_02_01_05;
}
impl DilithiumParams for Dilithium5Params {
    type PqPublicKey = dilithium5::PublicKey;
    type PqSecretKey = dilithium5::SecretKey;
    type PqDetachedSignature = dilithium5::DetachedSignature;

    fn public_key_bytes() -> usize {
        dilithium5::public_key_bytes()
    }
    fn secret_key_bytes() -> usize {
        dilithium5::secret_key_bytes()
    }

    fn keypair() -> (Self::PqPublicKey, Self::PqSecretKey) {
        dilithium5::keypair()
    }
    fn sign(sk: &Self::PqSecretKey, msg: &[u8]) -> Self::PqDetachedSignature {
        dilithium5::detached_sign(msg, sk)
    }
    fn verify(
        sig: &Self::PqDetachedSignature,
        msg: &[u8],
        pk: &Self::PqPublicKey,
    ) -> Result<(), Error> {
        dilithium5::verify_detached_signature(sig, msg, pk)
            .map_err(|_| Error::Signature(SignatureError::Verification))
    }
}

// ------------------- Newtype Wrappers for Dilithium Keys -------------------
// ------------------- Dilithium 密钥的 Newtype 包装器 -------------------

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DilithiumPublicKey<P: DilithiumParams> {
    bytes: Vec<u8>,
    _params: PhantomData<P>,
}

impl<P: DilithiumParams> Clone for DilithiumPublicKey<P> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            _params: PhantomData,
        }
    }
}

impl<P: DilithiumParams> PartialEq for DilithiumPublicKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<'a, P: DilithiumParams> From<&'a DilithiumPublicKey<P>> for DilithiumPublicKey<P> {
    fn from(key: &'a DilithiumPublicKey<P>) -> Self {
        key.clone()
    }
}

impl<P: DilithiumParams> TryFrom<&[u8]> for DilithiumPublicKey<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Key::from_bytes(bytes)
    }
}

#[derive(Debug, Zeroize, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[zeroize(drop)]
pub struct DilithiumSecretKey<P: DilithiumParams + Clone> {
    bytes: Zeroizing<Vec<u8>>,
    _params: PhantomData<P>,
}

impl<P: DilithiumParams> Key for DilithiumPublicKey<P> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != P::public_key_bytes() {
            return Err(Error::Key(KeyError::InvalidEncoding));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            _params: PhantomData,
        })
    }
    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.bytes.clone())
    }
}
impl<P: DilithiumParams> PublicKey for DilithiumPublicKey<P> {}

impl<P: DilithiumParams + Clone> Key for DilithiumSecretKey<P> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != P::secret_key_bytes() {
            return Err(Error::Key(KeyError::InvalidEncoding));
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes.to_vec()),
            _params: PhantomData,
        })
    }
    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.bytes.to_vec())
    }
}

impl<P: DilithiumParams + Clone> TryFrom<&[u8]> for DilithiumSecretKey<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Key::from_bytes(bytes)
    }
}

impl<P: DilithiumParams + Clone> PrivateKey<DilithiumPublicKey<P>> for DilithiumSecretKey<P> {}

// ------------------- Generic Dilithium Implementation -------------------
// ------------------- 通用 Dilithium 实现 -------------------

/// A generic struct representing the Dilithium cryptographic system.
///
/// This struct implements the complete Dilithium post-quantum signature scheme,
/// providing key generation, signing, and verification capabilities. It is
/// parameterized over different Dilithium security levels to allow compile-time
/// selection of the desired security/performance trade-off.
///
/// # Type Parameters
/// * `P` - The parameter set defining the security level (Dilithium2, 3, or 5)
///
/// # Security Guarantees
/// - Provides post-quantum security against both classical and quantum attacks
/// - Strong unforgeability under chosen message attacks (SUF-CMA)
/// - Constant-time implementation resistant to side-channel attacks
/// - Deterministic signatures for reproducible results
///
/// 一个通用结构体，表示 Dilithium 密码系统。
///
/// 此结构体实现了完整的 Dilithium 后量子签名方案，
/// 提供密钥生成、签名和验证功能。它在不同的 Dilithium 安全级别上参数化，
/// 以允许编译时选择所需的安全性/性能权衡。
///
/// # 类型参数
/// * `P` - 定义安全级别的参数集（Dilithium2、3 或 5）
///
/// # 安全保证
/// - 提供针对经典和量子攻击的后量子安全性
/// - 在选择消息攻击下的强不可伪造性 (SUF-CMA)
/// - 恒定时间实现，抵抗侧信道攻击
/// - 确定性签名以获得可重现的结果
#[derive(Clone, Debug, Default)]
pub struct DilithiumScheme<P: DilithiumParams> {
    _params: PhantomData<P>,
}

impl<P: DilithiumParams + Clone> AsymmetricKeySet for DilithiumScheme<P> {
    type PublicKey = DilithiumPublicKey<P>;
    type PrivateKey = DilithiumSecretKey<P>;
}

impl<P: DilithiumParams + Clone + 'static> Algorithm for DilithiumScheme<P> {
    fn name() -> String {
        format!("Dilithium-{}", P::NAME)
    }
    const ID: u32 = P::ID;
}

impl<P: DilithiumParams + Clone> KeyGenerator for DilithiumScheme<P> {
    fn generate_keypair() -> Result<(Self::PublicKey, Self::PrivateKey), Error> {
        let (pk, sk) = P::keypair();
        Ok((
            DilithiumPublicKey {
                bytes: pk.as_bytes().to_vec(),
                _params: PhantomData,
            },
            DilithiumSecretKey {
                bytes: Zeroizing::new(sk.as_bytes().to_vec()),
                _params: PhantomData,
            },
        ))
    }
}

impl<P: DilithiumParams + Clone> Signer for DilithiumScheme<P> {
    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Signature, Error> {
        let sk = PqSecretKey::from_bytes(&private_key.bytes)
            .map_err(|_| Error::Signature(SignatureError::Signing))?;
        let sig = P::sign(&sk, message);
        Ok(sig.as_bytes().to_vec())
    }
}

impl<P: DilithiumParams + Clone> Verifier for DilithiumScheme<P> {
    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), Error> {
        let pk = PqPublicKey::from_bytes(&public_key.bytes)
            .map_err(|_| Error::Key(KeyError::InvalidEncoding))?;
        let sig = PqDetachedSignature::from_bytes(signature.as_ref())
            .map_err(|_| Error::Signature(SignatureError::InvalidSignature))?;
        P::verify(&sig, message, &pk)
    }
}

// ------------------- Type Aliases for Specific Dilithium Schemes -------------------
// ------------------- 特定 Dilithium 方案的类型别名 -------------------

/// A type alias for the Dilithium2 scheme.
///
/// Dilithium2 方案的类型别名。
pub type Dilithium2 = DilithiumScheme<Dilithium2Params>;

/// A type alias for the Dilithium3 scheme.
///
/// Dilithium3 方案的类型别名。
pub type Dilithium3 = DilithiumScheme<Dilithium3Params>;

/// A type alias for the Dilithium5 scheme.
///
/// Dilithium5 方案的类型别名。
pub type Dilithium5 = DilithiumScheme<Dilithium5Params>;

// ------------------- Tests -------------------
// ------------------- 测试 -------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn run_dilithium_tests<P: DilithiumParams + Default + Clone + std::fmt::Debug>() {
        // Test key generation
        // 测试密钥生成
        let (pk, sk) = DilithiumScheme::<P>::generate_keypair().unwrap();
        assert_eq!(pk.to_bytes().unwrap().len(), P::public_key_bytes());
        assert_eq!(sk.to_bytes().unwrap().len(), P::secret_key_bytes());

        // Test key serialization
        // 测试密钥序列化
        let pk_bytes = pk.to_bytes().unwrap();
        let sk_bytes = sk.to_bytes().unwrap();
        let pk2 = DilithiumPublicKey::<P>::from_bytes(&pk_bytes).unwrap();
        let sk2 = DilithiumSecretKey::<P>::from_bytes(&sk_bytes).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(sk.to_bytes(), sk2.to_bytes());

        // Test sign/verify roundtrip
        // 测试签名/验证往返
        let message = b"this is the message to be signed";
        let signature = DilithiumScheme::<P>::sign(&sk, message).unwrap();
        assert!(DilithiumScheme::<P>::verify(&pk, message, &signature).is_ok());

        // Test tampered message verification fails
        // 测试篡改消息验证失败
        let tampered_message = b"this is a different message";
        assert!(DilithiumScheme::<P>::verify(&pk, tampered_message, &signature).is_err());

        // Test with empty message
        // 测试空消息
        let empty_message = b"";
        let signature_empty = DilithiumScheme::<P>::sign(&sk, empty_message).unwrap();
        assert!(DilithiumScheme::<P>::verify(&pk, empty_message, &signature_empty).is_ok());
    }

    #[test]
    fn test_dilithium2() {
        run_dilithium_tests::<Dilithium2Params>();
    }

    #[test]
    fn test_dilithium3() {
        run_dilithium_tests::<Dilithium3Params>();
    }

    #[test]
    fn test_dilithium5() {
        run_dilithium_tests::<Dilithium5Params>();
    }
}
