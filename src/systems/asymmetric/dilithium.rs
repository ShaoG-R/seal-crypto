//! Provides an implementation of the Dilithium post-quantum signature scheme.
//!
//! 提供了 Dilithium 后量子签名方案的实现。

use crate::errors::Error;
use crate::traits::{
    key::{KeyGenerator, PrivateKey, PublicKey},
    sign::{Signature, SignatureError, Signer, Verifier},
};
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use pqcrypto_traits::sign::{
    DetachedSignature as PqDetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use std::marker::PhantomData;
use zeroize::Zeroizing;

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
#[derive(Debug, Default)]
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
#[derive(Debug, Default)]
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
#[derive(Debug, Default)]
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

// ------------------- Generic Dilithium Implementation -------------------
// ------------------- 通用 Dilithium 实现 -------------------

/// A generic struct representing the Dilithium cryptographic system.
#[derive(Debug, Default)]
pub struct DilithiumScheme<P: DilithiumParams> {
    _params: PhantomData<P>,
}

impl<P: DilithiumParams> KeyGenerator for DilithiumScheme<P> {
    fn generate_keypair() -> Result<(PublicKey, PrivateKey), Error> {
        let (pk, sk) = P::keypair();
        Ok((
            pk.as_bytes().to_vec(),
            Zeroizing::new(sk.as_bytes().to_vec()),
        ))
    }
}

impl<P: DilithiumParams> Signer for DilithiumScheme<P> {
    type PrivateKey = PrivateKey;
    type Signature = Signature;

    fn sign(private_key: &PrivateKey, message: &[u8]) -> Result<Signature, Error> {
        if private_key.len() != P::secret_key_bytes() {
            return Err(SignatureError::InvalidPrivateKey.into());
        }
        let sk = P::PqSecretKey::from_bytes(private_key)
            .map_err(|_| SignatureError::InvalidPrivateKey)?;
        let signature = P::sign(&sk, message);
        Ok(signature.as_bytes().to_vec())
    }
}

impl<P: DilithiumParams> Verifier for DilithiumScheme<P> {
    type PublicKey = PublicKey;
    type Signature = Signature;

    fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<(), Error> {
        if public_key.len() != P::public_key_bytes() {
            return Err(SignatureError::InvalidPublicKey.into());
        }
        let pk =
            P::PqPublicKey::from_bytes(public_key).map_err(|_| SignatureError::InvalidPublicKey)?;
        let sig = P::PqDetachedSignature::from_bytes(signature)
            .map_err(|_| SignatureError::InvalidSignature)?;

        P::verify(&sig, message, &pk)
    }
}

// ------------------- Tests -------------------
// ------------------- 测试 -------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn run_dilithium_tests<P: DilithiumParams>() {
        type TestScheme<P> = DilithiumScheme<P>;

        // Test key generation
        let (pk, sk) = TestScheme::<P>::generate_keypair().unwrap();
        assert_eq!(pk.len(), P::public_key_bytes());
        assert_eq!(sk.len(), P::secret_key_bytes());

        // Test sign/verify roundtrip
        let message = b"this is the message to be signed";
        let signature = TestScheme::<P>::sign(&sk, message).unwrap();
        assert!(TestScheme::<P>::verify(&pk, message, &signature).is_ok());

        // Test tampered message verification fails
        let tampered_message = b"this is a different message";
        assert!(TestScheme::<P>::verify(&pk, tampered_message, &signature).is_err());

        // Test with empty message
        let empty_message = b"";
        let signature_empty = TestScheme::<P>::sign(&sk, empty_message).unwrap();
        assert!(TestScheme::<P>::verify(&pk, empty_message, &signature_empty).is_ok());
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
