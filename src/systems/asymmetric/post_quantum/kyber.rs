//! Provides an implementation of the Kyber post-quantum KEM.
//!
//! 提供了 Kyber 后量子 KEM 的实现。

use crate::errors::Error;
use crate::traits::{
    Algorithm, AsymmetricKeySet, EncapsulatedKey, Kem, KemError, Key, KeyError, KeyGenerator,
    PrivateKey, PublicKey, SharedSecret,
};
use pqcrypto_kyber::{kyber512, kyber768, kyber1024};
use pqcrypto_traits::kem::{
    Ciphertext as PqCiphertext, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
    SharedSecret as PqSharedSecret,
};
use std::convert::TryFrom;
use std::marker::PhantomData;
use zeroize::{Zeroize, Zeroizing};

// ------------------- Marker Structs and Trait for Kyber Parameters -------------------
// ------------------- 用于 Kyber 参数的标记结构体和 Trait -------------------

mod private {
    pub trait Sealed {}
}

/// A trait that defines the parameters for a specific Kyber security level.
/// This is a sealed trait, meaning only types within this crate can implement it.
///
/// 一个定义特定 Kyber 安全级别参数的 trait。
/// 这是一个密封的 trait，意味着只有此 crate 中的类型才能实现它。
pub trait KyberParams:
    private::Sealed + Send + Sync + 'static + Clone + Default
{
    const NAME: &'static str;
    const ID: u32;
    type PqPublicKey: PqPublicKey + Clone;
    type PqSecretKey: PqSecretKey + Clone;
    type PqCiphertext: PqCiphertext + Copy;
    type PqSharedSecret: PqSharedSecret;

    const PUBLIC_KEY_BYTES: usize;
    const SECRET_KEY_BYTES: usize;
    const CIPHERTEXT_BYTES: usize;

    fn keypair() -> (Self::PqPublicKey, Self::PqSecretKey);
    fn encapsulate(pk: &Self::PqPublicKey) -> (Self::PqSharedSecret, Self::PqCiphertext);
    fn decapsulate(sk: &Self::PqSecretKey, ct: &Self::PqCiphertext) -> Self::PqSharedSecret;
}

/// Marker struct for Kyber-512 parameters.
///
/// Kyber-512 参数的标记结构体。
#[derive(Debug, Default, Clone)]
pub struct Kyber512Params;
impl private::Sealed for Kyber512Params {}
impl KyberParams for Kyber512Params {
    const NAME: &'static str = "Kyber512";
    const ID: u32 = 0x01_02_02_01;
    type PqPublicKey = kyber512::PublicKey;
    type PqSecretKey = kyber512::SecretKey;
    type PqCiphertext = kyber512::Ciphertext;
    type PqSharedSecret = kyber512::SharedSecret;

    const PUBLIC_KEY_BYTES: usize = kyber512::public_key_bytes();
    const SECRET_KEY_BYTES: usize = kyber512::secret_key_bytes();
    const CIPHERTEXT_BYTES: usize = kyber512::ciphertext_bytes();

    fn keypair() -> (Self::PqPublicKey, Self::PqSecretKey) {
        kyber512::keypair()
    }
    fn encapsulate(pk: &Self::PqPublicKey) -> (Self::PqSharedSecret, Self::PqCiphertext) {
        kyber512::encapsulate(pk)
    }
    fn decapsulate(sk: &Self::PqSecretKey, ct: &Self::PqCiphertext) -> Self::PqSharedSecret {
        kyber512::decapsulate(ct, sk)
    }
}

/// Marker struct for Kyber-768 parameters.
///
/// Kyber-768 参数的标记结构体。
#[derive(Debug, Default, Clone)]
pub struct Kyber768Params;
impl private::Sealed for Kyber768Params {}
impl KyberParams for Kyber768Params {
    const NAME: &'static str = "Kyber768";
    const ID: u32 = 0x01_02_02_02;
    type PqPublicKey = kyber768::PublicKey;
    type PqSecretKey = kyber768::SecretKey;
    type PqCiphertext = kyber768::Ciphertext;
    type PqSharedSecret = kyber768::SharedSecret;

    const PUBLIC_KEY_BYTES: usize = kyber768::public_key_bytes();
    const SECRET_KEY_BYTES: usize = kyber768::secret_key_bytes();
    const CIPHERTEXT_BYTES: usize = kyber768::ciphertext_bytes();

    fn keypair() -> (Self::PqPublicKey, Self::PqSecretKey) {
        kyber768::keypair()
    }
    fn encapsulate(pk: &Self::PqPublicKey) -> (Self::PqSharedSecret, Self::PqCiphertext) {
        kyber768::encapsulate(pk)
    }
    fn decapsulate(sk: &Self::PqSecretKey, ct: &Self::PqCiphertext) -> Self::PqSharedSecret {
        kyber768::decapsulate(ct, sk)
    }
}

/// Marker struct for Kyber-1024 parameters.
///
/// Kyber-1024 参数的标记结构体。
#[derive(Debug, Default, Clone)]
pub struct Kyber1024Params;
impl private::Sealed for Kyber1024Params {}
impl KyberParams for Kyber1024Params {
    const NAME: &'static str = "Kyber1024";
    const ID: u32 = 0x01_02_02_03;
    type PqPublicKey = kyber1024::PublicKey;
    type PqSecretKey = kyber1024::SecretKey;
    type PqCiphertext = kyber1024::Ciphertext;
    type PqSharedSecret = kyber1024::SharedSecret;

    const PUBLIC_KEY_BYTES: usize = kyber1024::public_key_bytes();
    const SECRET_KEY_BYTES: usize = kyber1024::secret_key_bytes();
    const CIPHERTEXT_BYTES: usize = kyber1024::ciphertext_bytes();

    fn keypair() -> (Self::PqPublicKey, Self::PqSecretKey) {
        kyber1024::keypair()
    }
    fn encapsulate(pk: &Self::PqPublicKey) -> (Self::PqSharedSecret, Self::PqCiphertext) {
        kyber1024::encapsulate(pk)
    }
    fn decapsulate(sk: &Self::PqSecretKey, ct: &Self::PqCiphertext) -> Self::PqSharedSecret {
        kyber1024::decapsulate(ct, sk)
    }
}

// ------------------- Newtype Wrappers for Kyber Keys -------------------
// ------------------- Kyber 密钥的 Newtype 包装器 -------------------

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KyberPublicKey<P: KyberParams> {
    bytes: Vec<u8>,
    _params: PhantomData<P>,
}

impl<P: KyberParams> KyberPublicKey<P> {
    /// Returns the length of the public key in bytes.
    ///
    /// 返回公钥的字节长度。
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl<P: KyberParams> PartialEq for KyberPublicKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: KyberParams> Eq for KyberPublicKey<P> {}

impl<P: KyberParams> Clone for KyberPublicKey<P> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            _params: PhantomData,
        }
    }
}

impl<'a, P: KyberParams> From<&'a KyberPublicKey<P>> for KyberPublicKey<P> {
    fn from(key: &'a KyberPublicKey<P>) -> Self {
        key.clone()
    }
}

impl<P: KyberParams> TryFrom<&[u8]> for KyberPublicKey<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Key::from_bytes(bytes)
    }
}

impl<P: KyberParams> Key for KyberPublicKey<P> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != P::PUBLIC_KEY_BYTES {
            return Err(Error::Key(KeyError::InvalidEncoding));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            _params: PhantomData,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl<P: KyberParams> PublicKey for KyberPublicKey<P> {}

#[derive(Debug, Zeroize, Clone, Eq, PartialEq)]
#[zeroize(drop)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KyberSecretKey<P: KyberParams> {
    bytes: Zeroizing<Vec<u8>>,
    _params: PhantomData<P>,
}

impl<P: KyberParams> KyberSecretKey<P> {
    /// Returns the length of the secret key in bytes.
    ///
    /// 返回私钥的字节长度。
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl<P: KyberParams> Key for KyberSecretKey<P> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != P::SECRET_KEY_BYTES {
            return Err(Error::Key(KeyError::InvalidEncoding));
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes.to_vec()),
            _params: PhantomData,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

impl<P: KyberParams> TryFrom<&[u8]> for KyberSecretKey<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Key::from_bytes(bytes)
    }
}

impl<P: KyberParams + Clone> PrivateKey<KyberPublicKey<P>> for KyberSecretKey<P> {}

// ------------------- Generic Kyber KEM Implementation -------------------
// ------------------- 通用 Kyber KEM 实现 -------------------

/// A generic struct representing the Kyber cryptographic system for a given parameter set.
///
/// 一个通用结构体，表示给定参数集的 Kyber 密码系统。
#[derive(Clone, Debug, Default)]
pub struct KyberScheme<P: KyberParams> {
    _params: PhantomData<P>,
}

impl<P: KyberParams + Clone> AsymmetricKeySet for KyberScheme<P> {
    type PublicKey = KyberPublicKey<P>;
    type PrivateKey = KyberSecretKey<P>;
}

impl<P: KyberParams + Clone> Algorithm for KyberScheme<P> {
    fn name() -> String {
        format!("KYBER-KEM-{}", P::NAME)
    }
    const ID: u32 = P::ID;
}

impl<P: KyberParams + Clone> KeyGenerator for KyberScheme<P> {
    fn generate_keypair() -> Result<(Self::PublicKey, Self::PrivateKey), Error> {
        let (pk, sk) = P::keypair();
        Ok((
            KyberPublicKey {
                bytes: pk.as_bytes().to_vec(),
                _params: PhantomData,
            },
            KyberSecretKey {
                bytes: Zeroizing::new(sk.as_bytes().to_vec()),
                _params: PhantomData,
            },
        ))
    }
}

impl<P: KyberParams + Clone> Kem for KyberScheme<P> {
    type EncapsulatedKey = EncapsulatedKey;

    fn encapsulate(public_key: &Self::PublicKey) -> Result<(SharedSecret, EncapsulatedKey), Error> {
        let pk = PqPublicKey::from_bytes(&public_key.bytes)
            .map_err(|_| Error::Kem(KemError::InvalidPublicKey))?;
        let (ss, ct) = P::encapsulate(&pk);
        Ok((
            Zeroizing::new(ss.as_bytes().to_vec()),
            ct.as_bytes().to_vec(),
        ))
    }

    fn decapsulate(
        private_key: &Self::PrivateKey,
        encapsulated_key: &EncapsulatedKey,
    ) -> Result<SharedSecret, Error> {
        let sk = PqSecretKey::from_bytes(&private_key.bytes)
            .map_err(|_| Error::Kem(KemError::InvalidPrivateKey))?;
        let ct = PqCiphertext::from_bytes(encapsulated_key)
            .map_err(|_| Error::Kem(KemError::InvalidEncapsulatedKey))?;

        let ss = P::decapsulate(&sk, &ct);
        Ok(Zeroizing::new(ss.as_bytes().to_vec()))
    }
}

// ------------------- Type Aliases for Specific Kyber Schemes -------------------
// ------------------- 特定 Kyber 方案的类型别名 -------------------

/// A type alias for the Kyber-512 scheme.
///
/// Kyber-512 方案的类型别名。
pub type Kyber512 = KyberScheme<Kyber512Params>;

/// A type alias for the Kyber-768 scheme.
///
/// Kyber-768 方案的类型别名。
pub type Kyber768 = KyberScheme<Kyber768Params>;

/// A type alias for the Kyber-1024 scheme.
///
/// Kyber-1024 方案的类型别名。
pub type Kyber1024 = KyberScheme<Kyber1024Params>;

// ------------------- Tests -------------------
// ------------------- 测试 -------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Key;

    fn run_kyber_tests<P: KyberParams + Default + std::fmt::Debug>()
    where
        P: Clone,
    {
        let (pk, sk) = KyberScheme::<P>::generate_keypair().unwrap();
        assert_eq!(pk.to_bytes().len(), P::PUBLIC_KEY_BYTES);
        assert_eq!(sk.to_bytes().len(), P::SECRET_KEY_BYTES);

        // Test key serialization
        // 测试密钥序列化
        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();
        let pk2 = KyberPublicKey::<P>::from_bytes(&pk_bytes).unwrap();
        let sk2 = KyberSecretKey::<P>::from_bytes(&sk_bytes).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(sk.to_bytes(), sk2.to_bytes());

        // Test KEM roundtrip
        // 测试 KEM 往返
        let (ss1, encapsulated_key) = KyberScheme::<P>::encapsulate(&pk).unwrap();
        let ss2 = KyberScheme::<P>::decapsulate(&sk, &encapsulated_key).unwrap();
        assert_eq!(ss1, ss2);

        // Test wrong key decapsulation
        // 测试使用错误密钥解封装
        let (pk2, _sk2) = KyberScheme::<P>::generate_keypair().unwrap();
        let (ss_for_pk2, encapsulated_key_for_pk2) = KyberScheme::<P>::encapsulate(&pk2).unwrap();
        let wrong_ss = KyberScheme::<P>::decapsulate(&sk, &encapsulated_key_for_pk2).unwrap();
        assert_ne!(ss_for_pk2, wrong_ss);

        // Test tampered ciphertext
        // 测试篡改密文
        let (ss_orig, mut tampered_ct) = KyberScheme::<P>::encapsulate(&pk).unwrap();
        tampered_ct[0] ^= 1;
        let tampered_ss = KyberScheme::<P>::decapsulate(&sk, &tampered_ct).unwrap();
        assert_ne!(ss_orig, tampered_ss);
    }

    #[test]
    fn test_kyber_512() {
        run_kyber_tests::<Kyber512Params>();
    }

    #[test]
    fn test_kyber_768() {
        run_kyber_tests::<Kyber768Params>();
    }

    #[test]
    fn test_kyber_1024() {
        run_kyber_tests::<Kyber1024Params>();
    }
}
