//! Provides implementations for Elliptic Curve Diffie-Hellman (ECDH).
//!
//! This module supports key agreement using NIST P-256.
//! Keys are expected to be in PKCS#8 DER format.
//!
//! 提供了椭圆曲线迪菲-赫尔曼 (ECDH) 的实现。
//!
//! 本模块支持使用 NIST P-256 进行密钥协商。
//! 密钥应为 PKCS#8 DER 格式。

use crate::errors::Error;
use crate::traits::{
    Algorithm, AsymmetricKeySet, Key, KeyAgreement, KeyAgreementError, KeyError, KeyGenerator,
    PrivateKey, PublicKey, SharedSecret,
};
use elliptic_curve::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use p256::{NistP256, PublicKey as P256PublicKey, SecretKey, ecdh};
use rand_core_elliptic_curve::OsRng;
use std::convert::TryFrom;
use std::marker::PhantomData;
use zeroize::{Zeroize, Zeroizing};

// ------------------- Marker Structs and Trait for ECDH Parameters -------------------
// ------------------- 用于 ECDH 参数的标记结构体和 Trait -------------------

mod private {
    pub trait Sealed {}
}

/// A trait that defines the parameters for a specific ECDH scheme.
/// This is a sealed trait, meaning only types within this crate can implement it.
///
/// 一个定义特定 ECDH 方案参数的 trait。
/// 这是一个密封的 trait，意味着只有此 crate 中的类型才能实现它。
pub trait EcdhParams: private::Sealed + Send + Sync + 'static + Clone {
    const NAME: &'static str;
    type Curve: elliptic_curve::Curve + elliptic_curve::PrimeCurveArithmetic;

    fn validate_public_key(bytes: &[u8]) -> Result<(), Error>;
    fn validate_private_key(bytes: &[u8]) -> Result<(), Error>;
}

/// Marker struct for ECDH with NIST P-256 parameters.
///
/// 使用 NIST P-256 参数的 ECDH 的标记结构体。
#[derive(Debug, Default, Clone)]
pub struct EcdhP256Params;
impl private::Sealed for EcdhP256Params {}
impl EcdhParams for EcdhP256Params {
    const NAME: &'static str = "ECDH-P256";
    type Curve = NistP256;

    fn validate_public_key(bytes: &[u8]) -> Result<(), Error> {
        P256PublicKey::from_public_key_der(bytes)
            .map(|_| ())
            .map_err(|_| Error::KeyAgreement(KeyAgreementError::InvalidPeerPublicKey))
    }

    fn validate_private_key(bytes: &[u8]) -> Result<(), Error> {
        p256::SecretKey::from_pkcs8_der(bytes)
            .map(|_| ())
            .map_err(|_| Error::Key(KeyError::InvalidEncoding))
    }
}

// ------------------- Newtype Wrappers for ECDH Keys -------------------
// ------------------- ECDH 密钥的 Newtype 包装器 -------------------

#[derive(Debug)]
pub struct EcdhPublicKey<P: EcdhParams> {
    bytes: Vec<u8>,
    _params: PhantomData<P>,
}

impl<P: EcdhParams> PartialEq for EcdhPublicKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: EcdhParams> Eq for EcdhPublicKey<P> {}

impl<P: EcdhParams> Clone for EcdhPublicKey<P> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            _params: PhantomData,
        }
    }
}

impl<'a, P: EcdhParams> From<&'a EcdhPublicKey<P>> for EcdhPublicKey<P> {
    fn from(key: &'a EcdhPublicKey<P>) -> Self {
        key.clone()
    }
}

impl<P: EcdhParams> TryFrom<&[u8]> for EcdhPublicKey<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Key::from_bytes(bytes)
    }
}

impl<P: EcdhParams> Key for EcdhPublicKey<P> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        P::validate_public_key(bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            _params: PhantomData,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl<P: EcdhParams> PublicKey for EcdhPublicKey<P> {}

#[derive(Debug, Zeroize, Clone, Eq, PartialEq)]
#[zeroize(drop)]
pub struct EcdhPrivateKey<P: EcdhParams> {
    bytes: Zeroizing<Vec<u8>>,
    _params: PhantomData<P>,
}

impl<P: EcdhParams> Key for EcdhPrivateKey<P> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        P::validate_private_key(bytes)?;
        Ok(Self {
            bytes: Zeroizing::new(bytes.to_vec()),
            _params: PhantomData,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

impl<P: EcdhParams> TryFrom<&[u8]> for EcdhPrivateKey<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Key::from_bytes(bytes)
    }
}

impl<P: EcdhParams + Clone> PrivateKey<EcdhPublicKey<P>> for EcdhPrivateKey<P> {}

// ------------------- Generic ECDH Scheme Implementation -------------------
// ------------------- 通用 ECDH 方案实现 -------------------

/// A generic struct representing the ECDH scheme for a given parameter set.
///
/// 一个通用结构体，表示给定参数集的 ECDH 方案。
#[derive(Debug, Default)]
pub struct EcdhScheme<P: EcdhParams> {
    _params: PhantomData<P>,
}

impl<P: EcdhParams + Clone> AsymmetricKeySet for EcdhScheme<P> {
    type PublicKey = EcdhPublicKey<P>;
    type PrivateKey = EcdhPrivateKey<P>;
}

impl<P: EcdhParams + Clone> Algorithm for EcdhScheme<P> {
    const NAME: &'static str = P::NAME;
}

impl KeyGenerator for EcdhScheme<EcdhP256Params> {
    fn generate_keypair() -> Result<(Self::PublicKey, Self::PrivateKey), Error> {
        let secret = SecretKey::random(&mut OsRng);
        let public_key = secret.public_key();

        let private_key_der = secret
            .to_pkcs8_der()
            .map_err(|_| Error::Key(KeyError::GenerationFailed))?;

        let public_key_der = public_key
            .to_public_key_der()
            .map_err(|_| Error::Key(KeyError::GenerationFailed))?;

        Ok((
            EcdhPublicKey {
                bytes: public_key_der.as_bytes().to_vec(),
                _params: PhantomData,
            },
            EcdhPrivateKey {
                bytes: Zeroizing::new(private_key_der.as_bytes().to_vec()),
                _params: PhantomData,
            },
        ))
    }
}

impl KeyAgreement for EcdhScheme<EcdhP256Params> {
    fn agree(
        private_key: &Self::PrivateKey,
        public_key: &Self::PublicKey,
    ) -> Result<SharedSecret, Error> {
        let pk = P256PublicKey::from_public_key_der(&public_key.bytes)
            .map_err(|_| Error::KeyAgreement(KeyAgreementError::InvalidPeerPublicKey))?;

        let sk = SecretKey::from_pkcs8_der(&private_key.bytes)
            .map_err(|_| Error::Key(KeyError::InvalidEncoding))?;
        let shared_secret = ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());

        Ok(Zeroizing::new(shared_secret.raw_secret_bytes().to_vec()))
    }
}

// ------------------- Type Aliases for Specific ECDH Schemes -------------------
// ------------------- 特定 ECDH 方案的类型别名 -------------------

/// A type alias for the ECDH P-256 scheme.
///
/// ECDH P-256 方案的类型别名。
pub type EcdhP256 = EcdhScheme<EcdhP256Params>;

// ------------------- Tests -------------------
// ------------------- 测试 -------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_p256_key_agreement() {
        // Alice generates a keypair
        let (alice_pk, alice_sk) = EcdhP256::generate_keypair().unwrap();

        // Bob generates a keypair
        let (bob_pk, bob_sk) = EcdhP256::generate_keypair().unwrap();

        // They perform key agreement
        let alice_shared = EcdhP256::agree(&alice_sk, &bob_pk).unwrap();
        let bob_shared = EcdhP256::agree(&bob_sk, &alice_pk).unwrap();

        // The shared secrets must be equal
        assert_eq!(alice_shared, bob_shared);

        // Test key serialization/deserialization
        let alice_pk_bytes = alice_pk.to_bytes();
        let alice_sk_bytes = alice_sk.to_bytes();

        let _ = EcdhPublicKey::<EcdhP256Params>::from_bytes(&alice_pk_bytes).unwrap();
        let alice_sk2 = EcdhPrivateKey::<EcdhP256Params>::from_bytes(&alice_sk_bytes).unwrap();

        let alice_shared2 = EcdhP256::agree(&alice_sk2, &bob_pk).unwrap();
        assert_eq!(alice_shared, alice_shared2);
    }
}
