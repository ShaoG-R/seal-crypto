//! Provides an implementation of the Kyber post-quantum KEM.
//!
//! 提供了 Kyber 后量子 KEM 的实现。

use crate::errors::Error;
use crate::traits::{
    kem::{EncapsulatedKey, Kem, KemError, SharedSecret},
    key::{KeyGenerator, PrivateKey, PublicKey},
};
use pqcrypto_kyber::{kyber1024, kyber512, kyber768};
use pqcrypto_traits::kem::{
    Ciphertext as PqCiphertext, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
    SharedSecret as PqSharedSecret,
};
use std::marker::PhantomData;
use zeroize::Zeroizing;

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
pub trait KyberParams: private::Sealed + Send + Sync + 'static {
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
#[derive(Debug, Default)]
pub struct Kyber512;
impl private::Sealed for Kyber512 {}
impl KyberParams for Kyber512 {
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
#[derive(Debug, Default)]
pub struct Kyber768;
impl private::Sealed for Kyber768 {}
impl KyberParams for Kyber768 {
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
#[derive(Debug, Default)]
pub struct Kyber1024;
impl private::Sealed for Kyber1024 {}
impl KyberParams for Kyber1024 {
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

// ------------------- Generic Kyber KEM Implementation -------------------
// ------------------- 通用 Kyber KEM 实现 -------------------

/// A generic struct representing the Kyber cryptographic system for a given parameter set.
///
/// 一个通用结构体，表示给定参数集的 Kyber 密码系统。
#[derive(Debug, Default)]
pub struct KyberScheme<P: KyberParams> {
    _params: PhantomData<P>,
}

impl<P: KyberParams> KeyGenerator for KyberScheme<P> {
    fn generate_keypair() -> Result<(PublicKey, PrivateKey), Error> {
        let (pk, sk) = P::keypair();
        Ok((
            pk.as_bytes().to_vec(),
            Zeroizing::new(sk.as_bytes().to_vec()),
        ))
    }
}

impl<P: KyberParams> Kem for KyberScheme<P> {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type EncapsulatedKey = EncapsulatedKey;

    fn encapsulate(public_key: &PublicKey) -> Result<(SharedSecret, EncapsulatedKey), Error> {
        if public_key.len() != P::PUBLIC_KEY_BYTES {
            return Err(KemError::InvalidPublicKey.into());
        }
        let pk = P::PqPublicKey::from_bytes(public_key).map_err(|_| KemError::InvalidPublicKey)?;
        let (ss, ct) = P::encapsulate(&pk);
        Ok((
            Zeroizing::new(ss.as_bytes().to_vec()),
            ct.as_bytes().to_vec(),
        ))
    }

    fn decapsulate(
        private_key: &PrivateKey,
        encapsulated_key: &EncapsulatedKey,
    ) -> Result<SharedSecret, Error> {
        if private_key.len() != P::SECRET_KEY_BYTES {
            return Err(KemError::InvalidPrivateKey.into());
        }
        if encapsulated_key.len() != P::CIPHERTEXT_BYTES {
            return Err(KemError::InvalidEncapsulatedKey.into());
        }
        let sk =
            P::PqSecretKey::from_bytes(private_key).map_err(|_| KemError::InvalidPrivateKey)?;
        let ct = P::PqCiphertext::from_bytes(encapsulated_key)
            .map_err(|_| KemError::InvalidEncapsulatedKey)?;

        let ss = P::decapsulate(&sk, &ct);
        Ok(Zeroizing::new(ss.as_bytes().to_vec()))
    }
}

// ------------------- Tests -------------------
// ------------------- 测试 -------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn run_kyber_tests<P: KyberParams>() {
        type TestScheme<P> = KyberScheme<P>;

        // Test key generation
        // 测试密钥生成
        let (pk, sk) = TestScheme::<P>::generate_keypair().unwrap();
        assert_eq!(pk.len(), P::PUBLIC_KEY_BYTES);
        assert_eq!(sk.len(), P::SECRET_KEY_BYTES);

        // Test KEM roundtrip
        // 测试 KEM 往返操作
        let (ss1, encapsulated_key) = TestScheme::<P>::encapsulate(&pk).unwrap();
        let ss2 = TestScheme::<P>::decapsulate(&sk, &encapsulated_key).unwrap();
        assert_eq!(ss1, ss2);

        // Test wrong key decapsulation
        // 测试使用错误密钥进行解封装
        let (pk2, _sk2) = TestScheme::<P>::generate_keypair().unwrap();
        let (ss_for_pk2, encapsulated_key_for_pk2) = TestScheme::<P>::encapsulate(&pk2).unwrap();
        let wrong_ss = TestScheme::<P>::decapsulate(&sk, &encapsulated_key_for_pk2).unwrap();
        assert_ne!(ss_for_pk2, wrong_ss);

        // Test tampered ciphertext
        // 测试篡改后的密文
        let (ss_orig, mut tampered_ct) = TestScheme::<P>::encapsulate(&pk).unwrap();
        tampered_ct[0] ^= 1;
        let tampered_ss = TestScheme::<P>::decapsulate(&sk, &tampered_ct).unwrap();
        assert_ne!(ss_orig, tampered_ss);
    }

    #[test]
    fn test_kyber_512() {
        run_kyber_tests::<Kyber512>();
    }

    #[test]
    fn test_kyber_768() {
        run_kyber_tests::<Kyber768>();
    }

    #[test]
    fn test_kyber_1024() {
        run_kyber_tests::<Kyber1024>();
    }
} 