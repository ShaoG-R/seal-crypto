/// `sha2` family hash functions
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
    #[cfg(feature = "pbkdf2-default")]
    fn pbkdf2_hmac(password: &[u8], salt: &[u8], rounds: u32, okm: &mut [u8]);

    /// Expands a key using HKDF with the hasher.
    #[cfg(feature = "hkdf-default")]
    fn hkdf_expand(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: Option<&[u8]>,
        okm: &mut [u8],
    ) -> Result<(), KdfError>;

    /// Encrypts data using RSA-OAEP with the hasher.
    #[cfg(feature = "rsa-default")]
    fn rsa_oaep_encrypt(key: &RsaPublicKey, msg: &[u8]) -> Result<Vec<u8>, Error>;

    /// Decrypts data using RSA-OAEP with the hasher.
    #[cfg(feature = "rsa-default")]
    fn rsa_oaep_decrypt(key: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error>;

    /// Signs a message using RSA-PSS with the hasher.
    #[cfg(feature = "rsa-default")]
    fn rsa_pss_sign(key: &RsaPrivateKey, msg: &[u8]) -> Result<Vec<u8>, Error>;

    /// Verifies a signature using RSA-PSS with the hasher.
    #[cfg(feature = "rsa-default")]
    fn rsa_pss_verify(key: &RsaPublicKey, msg: &[u8], sig: &[u8]) -> Result<(), Error>;
}

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