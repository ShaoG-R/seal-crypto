//! Provides implementations for Elliptic Curve Cryptography (ECC).
//!
//! This module supports:
//! - ECDSA (Elliptic Curve Digital Signature Algorithm)
//! - EdDSA (Edwards-curve Digital Signature Algorithm)
//!
//! Keys are expected to be in PKCS#8 DER format.
//!
//! 提供了椭圆曲线密码学 (ECC) 的实现。
//!
//! 本模块支持：
//! - ECDSA (椭圆曲线数字签名算法)
//! - EdDSA (爱德华兹曲线数字签名算法)
//!
//! 密钥应为 PKCS#8 DER 格式。

use crate::errors::Error;
use crate::traits::{
    Algorithm, AsymmetricKeySet, Key, KeyError, KeyGenerator, PrivateKey, PublicKey, Signature,
    SignatureError, Signer, Verifier,
};
use ecdsa::{signature::RandomizedSigner, Signature as EcdsaSignature, SigningKey, VerifyingKey};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519DalekSigner, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use elliptic_curve::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use p256::{ecdsa::Signature as P256Signature, NistP256, SecretKey};
use rand_core_elliptic_curve::{OsRng, RngCore};
use std::convert::TryFrom;
use std::marker::PhantomData;
use zeroize::{Zeroize, Zeroizing};

// ------------------- Marker Structs and Trait for ECC Parameters -------------------
// ------------------- 用于 ECC 参数的标记结构体和 Trait -------------------

mod private {
    pub trait Sealed {}
}

/// A trait that defines the parameters for a specific ECC scheme.
/// This is a sealed trait, meaning only types within this crate can implement it.
///
/// 一个定义特定 ECC 方案参数的 trait。
/// 这是一个密封的 trait，意味着只有此 crate 中的类型才能实现它。
pub trait EccParams: private::Sealed + Send + Sync + 'static {
    const NAME: &'static str;

    fn generate_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error>;
    fn sign(private_key_der: &[u8], message: &[u8]) -> Result<Signature, Error>;
    fn verify(public_key_der: &[u8], message: &[u8], signature: &Signature) -> Result<(), Error>;
    fn validate_public_key(bytes: &[u8]) -> Result<(), Error>;
    fn validate_private_key(bytes: &[u8]) -> Result<(), Error>;
}

/// Marker struct for ECDSA P-256 parameters.
///
/// ECDSA P-256 参数的标记结构体。
#[derive(Debug, Default, Clone)]
pub struct EcdsaP256Params;
impl private::Sealed for EcdsaP256Params {}
impl EccParams for EcdsaP256Params {
    const NAME: &'static str = "ECDSA-P256-SHA256";

    fn generate_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
        let private_key = SecretKey::random(&mut OsRng);
        let public_key = private_key.public_key();

        let private_key_der = private_key
            .to_pkcs8_der()
            .map_err(|_| Error::Key(KeyError::GenerationFailed))?;
        let public_key_der = public_key
            .to_public_key_der()
            .map_err(|_| Error::Key(KeyError::GenerationFailed))?;

        Ok((
            public_key_der.as_bytes().to_vec(),
            Zeroizing::new(private_key_der.as_bytes().to_vec()),
        ))
    }

    fn sign(private_key_der: &[u8], message: &[u8]) -> Result<Signature, Error> {
        let secret_key = SecretKey::from_pkcs8_der(private_key_der)
            .map_err(|_| Error::Signature(SignatureError::Signing))?;
        let signing_key: SigningKey<NistP256> = SigningKey::from(&secret_key);
        let mut rng = OsRng;
        let signature: P256Signature = signing_key.sign_with_rng(&mut rng, message);
        Ok(Signature(signature.to_vec()))
    }

    fn verify(public_key_der: &[u8], message: &[u8], signature: &Signature) -> Result<(), Error> {
        let verifying_key = VerifyingKey::<NistP256>::from_public_key_der(public_key_der)
            .map_err(|_| Error::Signature(SignatureError::Verification))?;
        let ecdsa_signature = EcdsaSignature::from_slice(signature.as_ref())
            .map_err(|_| Error::Signature(SignatureError::InvalidSignature))?;

        use signature::Verifier as _;
        verifying_key
            .verify(message, &ecdsa_signature)
            .map_err(|_| Error::Signature(SignatureError::Verification))
    }

    fn validate_public_key(bytes: &[u8]) -> Result<(), Error> {
        VerifyingKey::<NistP256>::from_public_key_der(bytes)
            .map(|_| ())
            .map_err(|_| Error::Key(KeyError::InvalidEncoding))
    }

    fn validate_private_key(bytes: &[u8]) -> Result<(), Error> {
        SecretKey::from_pkcs8_der(bytes)
            .map(|_| ())
            .map_err(|_| Error::Key(KeyError::InvalidEncoding))
    }
}

/// Marker struct for Ed25519 parameters.
///
/// Ed25519 参数的标记结构体。
#[derive(Debug, Default, Clone)]
pub struct Ed25519Params;
impl private::Sealed for Ed25519Params {}
impl EccParams for Ed25519Params {
    const NAME: &'static str = "Ed25519";

    fn generate_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
        let mut secret_bytes = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut secret_bytes)
            .map_err(|_| Error::Key(KeyError::GenerationFailed))?;
        let signing_key = Ed25519SigningKey::from_bytes(&secret_bytes);
        let public_key = signing_key.verifying_key();

        let private_key_der = signing_key
            .to_pkcs8_der()
            .map_err(|_| Error::Key(KeyError::GenerationFailed))?;
        let public_key_der = public_key
            .to_public_key_der()
            .map_err(|_| Error::Key(KeyError::GenerationFailed))?;

        Ok((
            public_key_der.as_bytes().to_vec(),
            Zeroizing::new(private_key_der.as_bytes().to_vec()),
        ))
    }

    fn sign(private_key_der: &[u8], message: &[u8]) -> Result<Signature, Error> {
        let signing_key = Ed25519SigningKey::from_pkcs8_der(private_key_der)
            .map_err(|_| Error::Signature(SignatureError::Signing))?;
        let signature = signing_key.sign(message);
        Ok(Signature(signature.to_bytes().to_vec()))
    }

    fn verify(public_key_der: &[u8], message: &[u8], signature: &Signature) -> Result<(), Error> {
        let verifying_key = Ed25519VerifyingKey::from_public_key_der(public_key_der)
            .map_err(|_| Error::Signature(SignatureError::Verification))?;
        let ed_signature = Ed25519Signature::from_slice(signature.as_ref())
            .map_err(|_| Error::Signature(SignatureError::InvalidSignature))?;

        use ed25519_dalek::Verifier as _;
        verifying_key
            .verify(message, &ed_signature)
            .map_err(|_| Error::Signature(SignatureError::Verification))
    }

    fn validate_public_key(bytes: &[u8]) -> Result<(), Error> {
        Ed25519VerifyingKey::from_public_key_der(bytes)
            .map(|_| ())
            .map_err(|_| Error::Key(KeyError::InvalidEncoding))
    }

    fn validate_private_key(bytes: &[u8]) -> Result<(), Error> {
        Ed25519SigningKey::from_pkcs8_der(bytes)
            .map(|_| ())
            .map_err(|_| Error::Key(KeyError::InvalidEncoding))
    }
}

// ------------------- Newtype Wrappers for ECC Keys -------------------
// ------------------- ECC 密钥的 Newtype 包装器 -------------------

#[derive(Debug)]
pub struct EccPublicKey<P: EccParams> {
    bytes: Vec<u8>,
    _params: PhantomData<P>,
}

impl<P: EccParams> PartialEq for EccPublicKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: EccParams> Eq for EccPublicKey<P> {}

impl<P: EccParams> Clone for EccPublicKey<P> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            _params: PhantomData,
        }
    }
}

impl<'a, P: EccParams> From<&'a EccPublicKey<P>> for EccPublicKey<P> {
    fn from(key: &'a EccPublicKey<P>) -> Self {
        key.clone()
    }
}

impl<P: EccParams> TryFrom<&[u8]> for EccPublicKey<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Key::from_bytes(bytes)
    }
}

impl<P: EccParams> Key for EccPublicKey<P> {
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

impl<P: EccParams> PublicKey for EccPublicKey<P> {}

#[derive(Debug, Zeroize, Clone, Eq, PartialEq)]
#[zeroize(drop)]
pub struct EccPrivateKey<P: EccParams> {
    bytes: Zeroizing<Vec<u8>>,
    _params: PhantomData<P>,
}

impl<P: EccParams> Key for EccPrivateKey<P> {
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

impl<P: EccParams> TryFrom<&[u8]> for EccPrivateKey<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Key::from_bytes(bytes)
    }
}

impl<P: EccParams + Clone> PrivateKey<EccPublicKey<P>> for EccPrivateKey<P> {}

// ------------------- Generic ECC Scheme Implementation -------------------
// ------------------- 通用 ECC 方案实现 -------------------

/// A generic struct representing the ECC signature scheme for a given parameter set.
///
/// 一个通用结构体，表示给定参数集的 ECC 签名方案。
#[derive(Debug, Default)]
pub struct EccScheme<P: EccParams> {
    _params: PhantomData<P>,
}

impl<P: EccParams + Clone> AsymmetricKeySet for EccScheme<P> {
    type PublicKey = EccPublicKey<P>;
    type PrivateKey = EccPrivateKey<P>;
}

impl<P: EccParams + Clone> Algorithm for EccScheme<P> {
    const NAME: &'static str = P::NAME;
}

impl<P: EccParams + Clone> KeyGenerator for EccScheme<P> {
    fn generate_keypair() -> Result<(Self::PublicKey, Self::PrivateKey), Error> {
        let (pk_bytes, sk_bytes) = P::generate_keypair()?;
        Ok((
            EccPublicKey {
                bytes: pk_bytes,
                _params: PhantomData,
            },
            EccPrivateKey {
                bytes: sk_bytes,
                _params: PhantomData,
            },
        ))
    }
}

impl<P: EccParams + Clone> Signer for EccScheme<P> {
    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Signature, Error> {
        P::sign(&private_key.bytes, message)
    }
}

impl<P: EccParams + Clone> Verifier for EccScheme<P> {
    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), Error> {
        P::verify(&public_key.bytes, message, signature)
    }
}

// ------------------- Type Aliases for Specific ECC Schemes -------------------
// ------------------- 特定 ECC 方案的类型别名 -------------------

/// A type alias for the ECDSA P-256 with SHA-256 scheme.
///
/// 使用 SHA-256 的 ECDSA P-256 方案的类型别名。
pub type EcdsaP256 = EccScheme<EcdsaP256Params>;

/// A type alias for the Ed25519 scheme.
///
/// Ed25519 方案的类型别名。
pub type Ed25519 = EccScheme<Ed25519Params>;

// ------------------- Tests -------------------
// ------------------- 测试 -------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Debug;

    fn run_ecc_scheme_tests<P>()
    where
        P: EccParams + Clone + Debug,
    {
        // Test key generation
        let (pk, sk) = EccScheme::<P>::generate_keypair().unwrap();

        // Test key serialization/deserialization
        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();

        let pk2 = EccPublicKey::<P>::from_bytes(&pk_bytes).unwrap();
        let sk2 = EccPrivateKey::<P>::from_bytes(&sk_bytes).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(sk.to_bytes(), sk2.to_bytes());

        // Test sign/verify roundtrip
        let message = b"this is the message to be signed";
        let signature = EccScheme::<P>::sign(&sk, message).unwrap();
        EccScheme::<P>::verify(&pk, message, &signature).unwrap();

        // Test tampered message verification fails
        let tampered_message = b"this is a different message";
        assert!(EccScheme::<P>::verify(&pk, tampered_message, &signature).is_err());

        // Test with empty message
        let empty_message = b"";
        let signature_empty = EccScheme::<P>::sign(&sk, empty_message).unwrap();
        EccScheme::<P>::verify(&pk, empty_message, &signature_empty).unwrap();
    }

    #[test]
    fn test_ecdsa_p256() {
        run_ecc_scheme_tests::<EcdsaP256Params>();
    }

    #[test]
    fn test_ed25519() {
        run_ecc_scheme_tests::<Ed25519Params>();
    }
}
