//! Provides an implementation of the Dilithium post-quantum signature scheme.
//!
//! 提供了 Dilithium 后量子签名方案的实现。

use crate::errors::Error;
use crate::traits::{
    key::{self, KeyGenerator},
    sign::{Signature, SignatureError, Signer, Verifier},
};
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
pub trait DilithiumParams: private::Sealed + Send + Sync + 'static {
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

/// Marker struct for Dilithium2.
#[derive(Debug, Default, Clone)]
pub struct Dilithium2;
impl private::Sealed for Dilithium2 {}
impl DilithiumParams for Dilithium2 {
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
            .map_err(|_| SignatureError::Verification.into())
    }
}

/// Marker struct for Dilithium3.
#[derive(Debug, Default, Clone)]
pub struct Dilithium3;
impl private::Sealed for Dilithium3 {}
impl DilithiumParams for Dilithium3 {
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
            .map_err(|_| SignatureError::Verification.into())
    }
}

/// Marker struct for Dilithium5.
#[derive(Debug, Default, Clone)]
pub struct Dilithium5;
impl private::Sealed for Dilithium5 {}
impl DilithiumParams for Dilithium5 {
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
            .map_err(|_| SignatureError::Verification.into())
    }
}

// ------------------- Newtype Wrappers for Dilithium Keys -------------------
// ------------------- Dilithium 密钥的 Newtype 包装器 -------------------

#[derive(Debug, Eq)]
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
        key::Key::from_bytes(bytes)
    }
}

#[derive(Debug, Zeroize, Clone, Eq, PartialEq)]
#[zeroize(drop)]
pub struct DilithiumSecretKey<P: DilithiumParams + Clone> {
    bytes: Zeroizing<Vec<u8>>,
    _params: PhantomData<P>,
}

impl<P: DilithiumParams> key::Key for DilithiumPublicKey<P> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != P::public_key_bytes() {
            return Err(Error::from(SignatureError::InvalidSignature));
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
impl<P: DilithiumParams> key::PublicKey for DilithiumPublicKey<P> {}

impl<P: DilithiumParams + Clone> key::Key for DilithiumSecretKey<P> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != P::secret_key_bytes() {
            return Err(Error::from(SignatureError::InvalidSignature));
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

impl<P: DilithiumParams + Clone> TryFrom<&[u8]> for DilithiumSecretKey<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        key::Key::from_bytes(bytes)
    }
}

impl<P: DilithiumParams + Clone> key::PrivateKey<DilithiumPublicKey<P>> for DilithiumSecretKey<P> {}

// ------------------- Generic Dilithium Implementation -------------------
// ------------------- 通用 Dilithium 实现 -------------------

/// A generic struct representing the Dilithium cryptographic system.
#[derive(Debug, Default)]
pub struct DilithiumScheme<P: DilithiumParams> {
    _params: PhantomData<P>,
}

impl<P: DilithiumParams + Clone> key::AsymmetricKeySet for DilithiumScheme<P> {
    type PublicKey = DilithiumPublicKey<P>;
    type PrivateKey = DilithiumSecretKey<P>;
}

impl<P: DilithiumParams + Clone + 'static> key::Algorithm for DilithiumScheme<P> {
    const NAME: &'static str = "Dilithium";
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
            .map_err(|_| Error::from(SignatureError::Signing))?;
        let sig = P::sign(&sk, message);
        Ok(Signature(sig.as_bytes().to_vec()))
    }
}

impl<P: DilithiumParams + Clone> Verifier for DilithiumScheme<P> {
    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), Error> {
        let pk = PqPublicKey::from_bytes(&public_key.bytes)
            .map_err(|_| Error::from(SignatureError::Verification))?;
        let sig = PqDetachedSignature::from_bytes(signature.as_ref())
            .map_err(|_| Error::from(SignatureError::InvalidSignature))?;
        P::verify(&sig, message, &pk)
    }
}

// ------------------- Tests -------------------
// ------------------- 测试 -------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::key::Key;

    fn run_dilithium_tests<P: DilithiumParams + Default + Clone + std::fmt::Debug>() {
        // Test key generation
        let (pk, sk) = DilithiumScheme::<P>::generate_keypair().unwrap();
        assert_eq!(pk.to_bytes().len(), P::public_key_bytes());
        assert_eq!(sk.to_bytes().len(), P::secret_key_bytes());

        // Test key serialization
        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();
        let pk2 = DilithiumPublicKey::<P>::from_bytes(&pk_bytes).unwrap();
        let sk2 = DilithiumSecretKey::<P>::from_bytes(&sk_bytes).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(sk.to_bytes(), sk2.to_bytes());

        // Test sign/verify roundtrip
        let message = b"this is the message to be signed";
        let signature = DilithiumScheme::<P>::sign(&sk, message).unwrap();
        assert!(DilithiumScheme::<P>::verify(&pk, message, &signature).is_ok());

        // Test tampered message verification fails
        let tampered_message = b"this is a different message";
        assert!(DilithiumScheme::<P>::verify(&pk, tampered_message, &signature).is_err());

        // Test with empty message
        let empty_message = b"";
        let signature_empty = DilithiumScheme::<P>::sign(&sk, empty_message).unwrap();
        assert!(DilithiumScheme::<P>::verify(&pk, empty_message, &signature_empty).is_ok());
    }

    #[test]
    fn test_dilithium2() {
        run_dilithium_tests::<Dilithium2>();
    }

    #[test]
    fn test_dilithium3() {
        run_dilithium_tests::<Dilithium3>();
    }

    #[test]
    fn test_dilithium5() {
        run_dilithium_tests::<Dilithium5>();
    }
}
