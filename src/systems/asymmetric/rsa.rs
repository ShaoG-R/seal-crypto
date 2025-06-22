//! Provides an implementation of KEM and Signatures using RSA.
//!
//! This module uses:
//! - RSA-OAEP for the KEM functionality.
//! - RSA-PSS for the signature functionality.
//! Keys are expected to be in PKCS#8 DER format.
//!
//! 提供了使用 RSA 的 KEM 和签名实现。
//!
//! 本模块使用：
//! - RSA-OAEP 用于 KEM 功能。
//! - RSA-PSS 用于签名功能。
//! 密钥应为 PKCS#8 DER 格式。

use crate::errors::Error;
use crate::traits::{
    hash::Hasher,
    kem::{EncapsulatedKey, Kem, KemError, SharedSecret},
    key::{KeyGenerator, PrivateKey, PublicKey},
    sign::{Signature, SignatureError, Signer, Verifier},
};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    pss::{Signature as PssSignature, SigningKey, VerifyingKey},
    rand_core::{OsRng, RngCore},
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use std::marker::PhantomData;
use zeroize::Zeroizing;

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
pub trait RsaKeyParams: private::Sealed + Send + Sync + 'static {
    /// The number of bits for the RSA key.
    ///
    /// RSA 密钥的位数。
    const KEY_BITS: usize;
}

/// Marker struct for RSA with a 2048-bit key.
///
/// RSA-2048 的标记结构体。
#[derive(Debug, Default)]
pub struct Rsa2048;
impl private::Sealed for Rsa2048 {}
impl RsaKeyParams for Rsa2048 {
    const KEY_BITS: usize = 2048;
}

/// Marker struct for RSA with a 4096-bit key.
///
/// RSA-4096 的标记结构体。
#[derive(Debug, Default)]
pub struct Rsa4096;
impl private::Sealed for Rsa4096 {}
impl RsaKeyParams for Rsa4096 {
    const KEY_BITS: usize = 4096;
}

// ------------------- Generic RSA Implementation -------------------
// ------------------- 通用 RSA 实现 -------------------

const SHARED_SECRET_SIZE: usize = 32;

/// A generic struct representing the RSA cryptographic scheme.
/// It is generic over the RSA key parameters (key size) and the hash function.
///
/// 一个通用结构体，表示 RSA 密码学方案。
/// 它在 RSA 密钥参数（密钥大小）和哈希函数上是通用的。
#[derive(Debug, Default)]
pub struct RsaScheme<KP: RsaKeyParams, H: Hasher> {
    _key_params: PhantomData<KP>,
    _hasher: PhantomData<H>,
}

impl<KP: RsaKeyParams, H: Hasher> KeyGenerator for RsaScheme<KP, H> {
    fn generate_keypair() -> Result<(PublicKey, PrivateKey), Error> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, KP::KEY_BITS).map_err(Error::Rsa)?;
        let public_key = private_key.to_public_key();

        let private_key_der = private_key
            .to_pkcs8_der()
            .map_err(|e| Error::Rsa(e.into()))?;
        let public_key_der = public_key
            .to_public_key_der()
            .map_err(|e| Error::Rsa(rsa::pkcs8::Error::from(e).into()))?;

        Ok((
            public_key_der.as_bytes().to_vec(),
            Zeroizing::new(private_key_der.as_bytes().to_vec()),
        ))
    }
}

impl<KP: RsaKeyParams, H: Hasher> Kem for RsaScheme<KP, H> {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type EncapsulatedKey = EncapsulatedKey;

    fn encapsulate(public_key: &PublicKey) -> Result<(SharedSecret, EncapsulatedKey), Error> {
        let mut rng = OsRng;
        let rsa_public_key = RsaPublicKey::from_public_key_der(public_key)
            .map_err(|_| KemError::InvalidPublicKey)?;

        let mut shared_secret_bytes = vec![0u8; SHARED_SECRET_SIZE];
        rng.fill_bytes(&mut shared_secret_bytes);

        let padding = Oaep::new::<H::Digest>();
        let encapsulated_key = rsa_public_key
            .encrypt(&mut rng, padding, &shared_secret_bytes)
            .map_err(|_| KemError::Encapsulation)?;

        Ok((Zeroizing::new(shared_secret_bytes), encapsulated_key))
    }

    fn decapsulate(
        private_key: &PrivateKey,
        encapsulated_key: &EncapsulatedKey,
    ) -> Result<SharedSecret, Error> {
        let rsa_private_key =
            RsaPrivateKey::from_pkcs8_der(private_key).map_err(|_| KemError::InvalidPrivateKey)?;

        let padding = Oaep::new::<H::Digest>();
        let shared_secret_bytes = rsa_private_key
            .decrypt(padding, encapsulated_key)
            .map_err(|_| KemError::Decapsulation)?;

        Ok(Zeroizing::new(shared_secret_bytes))
    }
}

impl<KP: RsaKeyParams, H: Hasher> Signer for RsaScheme<KP, H> {
    type PrivateKey = PrivateKey;
    type Signature = Signature;

    fn sign(private_key: &PrivateKey, message: &[u8]) -> Result<Signature, Error> {
        let rsa_private_key = RsaPrivateKey::from_pkcs8_der(private_key)
            .map_err(|_| SignatureError::InvalidPrivateKey)?;
        let signing_key = SigningKey::<H::Digest>::new(rsa_private_key);
        let mut rng = OsRng;
        let signature = signing_key.sign_with_rng(&mut rng, message);
        Ok(signature.to_vec())
    }
}

impl<KP: RsaKeyParams, H: Hasher> Verifier for RsaScheme<KP, H> {
    type PublicKey = PublicKey;
    type Signature = Signature;

    fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<(), Error> {
        let rsa_public_key = RsaPublicKey::from_public_key_der(public_key)
            .map_err(|_| SignatureError::InvalidPublicKey)?;
        let verifying_key = VerifyingKey::<H::Digest>::new(rsa_public_key);
        let pss_signature = PssSignature::try_from(signature.as_slice())
            .map_err(|_| SignatureError::InvalidSignature)?;
        use rsa::signature::Verifier;
        Ok(verifying_key
            .verify(message, &pss_signature)
            .map_err(|_| SignatureError::Verification)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schemes::hash::{Sha256, Sha512};

    fn run_rsa_tests<KP: RsaKeyParams, H: Hasher>()
    where
        RsaScheme<KP, H>: KeyGenerator
            + Kem<PublicKey = Vec<u8>, PrivateKey = Zeroizing<Vec<u8>>>
            + Signer<PrivateKey = PrivateKey, Signature = Signature>
            + Verifier<PublicKey = PublicKey, Signature = Signature>,
    {
        // Define the scheme to be tested based on the generic parameters.
        // 根据泛型参数定义要测试的方案。
        type TestScheme<H, KP> = RsaScheme<KP, H>;

        // Test key generation
        // 测试密钥生成
        let (pk, sk) = TestScheme::generate_keypair().unwrap();
        assert!(!pk.is_empty());
        assert!(!sk.is_empty());

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
    #[cfg(all(feature = "sha2"))]
    fn test_rsa_2048_sha256() {
        run_rsa_tests::<Rsa2048, Sha256>();
    }

    #[test]
    #[cfg(all(feature = "sha2"))]
    fn test_rsa_4096_sha512() {
        run_rsa_tests::<Rsa4096, Sha512>();
    }
}
