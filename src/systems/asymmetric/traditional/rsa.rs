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
    Algorithm, AsymmetricKeySet, EncapsulatedKey, Hasher, Kem, KemError, Key, KeyGenerator,
    PrivateKey, PublicKey, Sha256, SharedSecret, Signature, SignatureError, Signer, Verifier,
    KeyError,
};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    pss::{SigningKey, VerifyingKey},
    rand_core::{OsRng, RngCore},
    Oaep,
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
pub trait RsaKeyParams: private::Sealed + Send + Sync + 'static {
    /// The number of bits for the RSA key.
    ///
    /// RSA 密钥的位数。
    const KEY_BITS: usize;
}

/// Marker struct for RSA with a 2048-bit key.
///
/// RSA-2048 的标记结构体。
#[derive(Debug, Clone, Default)]
pub struct Rsa2048Params;
impl private::Sealed for Rsa2048Params {}
impl RsaKeyParams for Rsa2048Params {
    const KEY_BITS: usize = 2048;
}

/// Marker struct for RSA with a 4096-bit key.
///
/// RSA-4096 的标记结构体。
#[derive(Debug, Clone, Default)]
pub struct Rsa4096Params;
impl private::Sealed for Rsa4096Params {}
impl RsaKeyParams for Rsa4096Params {
    const KEY_BITS: usize = 4096;
}

// ------------------- Newtype Wrappers for RSA Keys -------------------
// ------------------- RSA 密钥的 Newtype 包装器 -------------------

#[derive(Clone, Debug)]
pub struct RsaPublicKey(rsa::RsaPublicKey);

#[derive(Debug, Zeroize, Clone, Eq, PartialEq)]
#[zeroize(drop)]
pub struct RsaPrivateKey(Zeroizing<Vec<u8>>);

impl Key for RsaPublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        rsa::RsaPublicKey::from_public_key_der(bytes)
            .map(RsaPublicKey)
            .map_err(|_| KeyError::InvalidEncoding.into())
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0
            .to_public_key_der()
            .expect("DER encoding of a valid key should not fail")
            .as_bytes()
            .to_vec()
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

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
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
#[derive(Debug, Default)]
pub struct RsaScheme<KP: RsaKeyParams, H: Hasher = Sha256> {
    _key_params: PhantomData<KP>,
    _hasher: PhantomData<H>,
}

impl<KP: RsaKeyParams, H: Hasher + 'static> AsymmetricKeySet for RsaScheme<KP, H> {
    type PublicKey = RsaPublicKey;
    type PrivateKey = RsaPrivateKey;
}

impl<KP: RsaKeyParams, H: Hasher + 'static> Algorithm for RsaScheme<KP, H> {
    const NAME: &'static str = "RSA-PSS";
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
        let rsa_public_key = &public_key.0;

        let mut shared_secret_bytes = vec![0u8; SHARED_SECRET_SIZE];
        rng.fill_bytes(&mut shared_secret_bytes);

        let padding = Oaep::new::<H::Digest>();
        let encapsulated_key = rsa_public_key
            .encrypt(&mut rng, padding, &shared_secret_bytes)
            .map_err(|_| KemError::Encapsulation)?;

        Ok((Zeroizing::new(shared_secret_bytes), encapsulated_key))
    }

    fn decapsulate(
        private_key: &RsaPrivateKey,
        encapsulated_key: &EncapsulatedKey,
    ) -> Result<SharedSecret, Error> {
        let rsa_private_key = rsa::RsaPrivateKey::from_pkcs8_der(&private_key.0)
            .map_err(|_| KemError::InvalidPrivateKey)?;

        let padding = Oaep::new::<H::Digest>();
        let shared_secret_bytes = rsa_private_key
            .decrypt(padding, encapsulated_key)
            .map_err(|_| KemError::Decapsulation)?;

        Ok(Zeroizing::new(shared_secret_bytes))
    }
}

impl<KP: RsaKeyParams, H: Hasher> Signer for RsaScheme<KP, H> {
    fn sign(private_key: &RsaPrivateKey, message: &[u8]) -> Result<Signature, Error> {
        let rsa_private_key = rsa::RsaPrivateKey::from_pkcs8_der(&private_key.0)
            .map_err(|_| Error::Signature(SignatureError::Signing))?;
        let signing_key = SigningKey::<H::Digest>::new(rsa_private_key);
        let mut rng = OsRng;
        let signature = signing_key.sign_with_rng(&mut rng, message);
        Ok(Signature(signature.to_vec()))
    }
}

impl<KP: RsaKeyParams, H: Hasher> Verifier for RsaScheme<KP, H> {
    fn verify(
        public_key: &RsaPublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), Error> {
        let verifying_key = VerifyingKey::<H::Digest>::new(public_key.0.clone());
        let pss_signature = rsa::pss::Signature::try_from(signature.as_ref())
            .map_err(|_| SignatureError::InvalidSignature)?;
        use rsa::signature::Verifier;
        Ok(verifying_key
            .verify(message, &pss_signature)
            .map_err(|_| SignatureError::Verification)?)
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
#[cfg(all(feature = "sha2"))]
pub type Rsa4096<Sha = Sha256> = RsaScheme<Rsa4096Params, Sha>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Key;
    use crate::traits::{Sha256, Sha512};

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
        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();
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
    #[cfg(all(feature = "sha2"))]
    fn test_rsa_2048_sha256() {
        run_rsa_tests::<Rsa2048Params, Sha256>();
    }

    #[test]
    #[cfg(all(feature = "sha2"))]
    fn test_rsa_4096_sha512() {
        run_rsa_tests::<Rsa4096Params, Sha512>();
    }
}
