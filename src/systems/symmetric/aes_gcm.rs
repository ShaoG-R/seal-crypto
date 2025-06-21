//! Provides implementations of symmetric AEAD encryption using AES-128-GCM and AES-256-GCM.

use crate::traits::{
    key::{KeyGenerator, PrivateKey, PublicKey as KpPublicKey}, // Renamed to avoid conflict
    symmetric::{
        AssociatedData, SymmetricCipher, SymmetricDecryptor, SymmetricEncryptor, SymmetricError,
        SymmetricKey,
    },
};
use crate::prelude::CryptoError;
use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use aes_gcm::aead::rand_core::RngCore;
use zeroize::Zeroizing;
use crate::errors::Error;
// ------------------- AES-256-GCM Implementation -------------------

/// A struct representing the AES-256-GCM symmetric cryptographic system.
#[derive(Debug, Default)]
pub struct Aes256GcmScheme;

impl SymmetricCipher for Aes256GcmScheme {
    const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;
}

impl SymmetricEncryptor for Aes256GcmScheme {
    type Key = SymmetricKey;

    /// Encrypts plaintext using AES-256-GCM.
    fn encrypt(
        key: &SymmetricKey,
        nonce: &[u8],
        plaintext: &[u8],
        aad: Option<AssociatedData>,
    ) -> Result<Vec<u8>, Error> {
        if key.len() != Self::KEY_SIZE {
            return Err(SymmetricError::InvalidKeySize)?;
        }
        if nonce.len() != Self::NONCE_SIZE {
            return Err(SymmetricError::InvalidNonceSize)?;
        }
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);

        let payload = Payload {
            msg: plaintext,
            aad: aad.unwrap_or(&[]),
        };
        cipher
            .encrypt(nonce, payload)
            .map_err(|e| SymmetricError::Encryption(Box::new(e)).into())
    }
}

impl SymmetricDecryptor for Aes256GcmScheme {
    type Key = SymmetricKey;

    /// Decrypts a ciphertext using AES-256-GCM.
    fn decrypt(
        key: &SymmetricKey,
        nonce: &[u8],
        ciphertext_with_tag: &[u8],
        aad: Option<AssociatedData>,
    ) -> Result<Vec<u8>, Error> {
        if key.len() != Self::KEY_SIZE {
            return Err(SymmetricError::InvalidKeySize)?;
        }
        if nonce.len() != Self::NONCE_SIZE {
            return Err(SymmetricError::InvalidNonceSize)?;
        }

        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);

        let payload = Payload {
            msg: ciphertext_with_tag,
            aad: aad.unwrap_or(&[]),
        };
        cipher
            .decrypt(nonce, payload)
            .map_err(|e| SymmetricError::Decryption(Box::new(e)).into())
    }
}

// Symmetric schemes don't have "key pairs", but we can implement KeyGenerator
// to provide a unified way to generate a symmetric key.
impl KeyGenerator for Aes256GcmScheme {
    // For symmetric keys, PublicKey is empty, PrivateKey holds the key.
    fn generate_keypair() -> Result<(KpPublicKey, PrivateKey), Error> {
        let mut key_bytes = vec![0u8; Self::KEY_SIZE];
        OsRng
            .try_fill_bytes(&mut key_bytes)
            .map_err(|e| CryptoError::KeyGeneration(Box::new(e)))?;
        Ok((vec![], Zeroizing::new(key_bytes)))
    }
}


// ------------------- AES-128-GCM Implementation -------------------


/// A struct representing the AES-128-GCM symmetric cryptographic system.
#[derive(Debug, Default)]
pub struct Aes128GcmScheme;

impl SymmetricCipher for Aes128GcmScheme {
    const KEY_SIZE: usize = 16;
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;
}

impl SymmetricEncryptor for Aes128GcmScheme {
    type Key = SymmetricKey;

    fn encrypt(
        key: &SymmetricKey,
        nonce: &[u8],
        plaintext: &[u8],
        aad: Option<AssociatedData>,
    ) -> Result<Vec<u8>, Error> {
        if key.len() != Self::KEY_SIZE {
            return Err(SymmetricError::InvalidKeySize)?;
        }
        if nonce.len() != Self::NONCE_SIZE {
            return Err(SymmetricError::InvalidNonceSize)?;
        }

        let key = aes_gcm::Key::<Aes128Gcm>::from_slice(key);
        let cipher = Aes128Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);

        let payload = Payload {
            msg: plaintext,
            aad: aad.unwrap_or(&[]),
        };
        cipher
            .encrypt(nonce, payload)
            .map_err(|e| SymmetricError::Encryption(Box::new(e)).into())
    }
}

impl SymmetricDecryptor for Aes128GcmScheme {
    type Key = SymmetricKey;

    fn decrypt(
        key: &SymmetricKey,
        nonce: &[u8],
        ciphertext_with_tag: &[u8],
        aad: Option<AssociatedData>,
    ) -> Result<Vec<u8>, Error> {
        if key.len() != Self::KEY_SIZE {
            return Err(SymmetricError::InvalidKeySize)?;
        }
        if nonce.len() != Self::NONCE_SIZE {
            return Err(SymmetricError::InvalidNonceSize)?;
        }

        let key = aes_gcm::Key::<Aes128Gcm>::from_slice(key);
        let cipher = Aes128Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);

        let payload = Payload {
            msg: ciphertext_with_tag,
            aad: aad.unwrap_or(&[]),
        };
        cipher
            .decrypt(nonce, payload)
            .map_err(|e| SymmetricError::Decryption(Box::new(e)).into())
    }
}

impl KeyGenerator for Aes128GcmScheme {
    fn generate_keypair() -> Result<(KpPublicKey, PrivateKey), Error> {
        let mut key_bytes = vec![0u8; Self::KEY_SIZE];
        OsRng
            .try_fill_bytes(&mut key_bytes)
            .map_err(|e| CryptoError::KeyGeneration(Box::new(e)))?;
        Ok((vec![], Zeroizing::new(key_bytes)))
    }
}


// ------------------- Tests -------------------

#[cfg(test)]
mod tests {
    use crate::errors::Error;
    use super::*;
    fn test_roundtrip<'a, S>(key: &SymmetricKey)
    where
        S: SymmetricEncryptor<Key = Zeroizing<Vec<u8>>>
            + SymmetricDecryptor<Key = Zeroizing<Vec<u8>>>,
    {
        let plaintext = b"this is a secret message".to_vec();
        let aad = b"this is authenticated data".to_vec();
        let empty_vec = Vec::new();
        let mut nonce = vec![0u8; S::NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        // With AAD
        let ciphertext_aad = S::encrypt(key, &nonce, &plaintext, Some(&aad)).unwrap();
        let decrypted_aad = S::decrypt(key, &nonce, &ciphertext_aad, Some(&aad)).unwrap();
        assert_eq!(plaintext, decrypted_aad);

        // Without AAD
        let ciphertext_no_aad = S::encrypt(key, &nonce, &plaintext, None).unwrap();
        let decrypted_no_aad = S::decrypt(key, &nonce, &ciphertext_no_aad, None).unwrap();
        assert_eq!(plaintext, decrypted_no_aad);

        // Empty Plaintext with AAD
        let ciphertext_empty_pt = S::encrypt(key, &nonce, &empty_vec, Some(&aad)).unwrap();
        let decrypted_empty_pt = S::decrypt(key, &nonce, &ciphertext_empty_pt, Some(&aad)).unwrap();
        assert_eq!(empty_vec, decrypted_empty_pt);

        // Plaintext with Empty AAD
        let ciphertext_empty_aad = S::encrypt(key, &nonce, &plaintext, Some(&empty_vec)).unwrap();
        let decrypted_empty_aad =
            S::decrypt(key, &nonce, &ciphertext_empty_aad, Some(&empty_vec)).unwrap();
        assert_eq!(plaintext, decrypted_empty_aad);

        // Empty Plaintext and Empty AAD
        let ciphertext_all_empty =
            S::encrypt(key, &nonce, &empty_vec, Some(&empty_vec)).unwrap();
        let decrypted_all_empty =
            S::decrypt(key, &nonce, &ciphertext_all_empty, Some(&empty_vec)).unwrap();
        assert_eq!(empty_vec, decrypted_all_empty);

        // Failure cases
        assert!(matches!(
            S::decrypt(key, &nonce, &ciphertext_aad, None)
                .unwrap_err()
                .into(),
            Error::Symmetric(SymmetricError::Decryption(_))
        ));
        let mut tampered_ciphertext = ciphertext_aad.clone();
        tampered_ciphertext[0] ^= 1;
        assert!(matches!(
            S::decrypt(key, &nonce, &tampered_ciphertext, Some(&aad))
                .unwrap_err()
                .into(),
            Error::Symmetric(SymmetricError::Decryption(_))
        ));
        let mut tampered_aad = aad.clone();
        tampered_aad[0] ^= 1;
        assert!(matches!(
            S::decrypt(key, &nonce, &ciphertext_aad, Some(&tampered_aad))
                .unwrap_err()
                .into(),
            Error::Symmetric(SymmetricError::Decryption(_))
        ));

        // Decrypt with wrong nonce
        let mut wrong_nonce = nonce.clone();
        wrong_nonce[0] ^= 1;
        assert!(matches!(
            S::decrypt(key, &wrong_nonce, &ciphertext_aad, Some(&aad))
                .unwrap_err()
                .into(),
            Error::Symmetric(SymmetricError::Decryption(_))
        ));
    }

    #[test]
    fn test_aes256gcm_scheme() {
        let (_, key) = Aes256GcmScheme::generate_keypair().unwrap();
        test_roundtrip::<Aes256GcmScheme>(&key);
    }

    #[test]
    fn test_aes128gcm_scheme() {
        let (_, key) = Aes128GcmScheme::generate_keypair().unwrap();
        test_roundtrip::<Aes128GcmScheme>(&key);
    }

    fn test_invalid_inputs<S>(key: &SymmetricKey, nonce: &[u8], plaintext: &[u8])
    where
        S: SymmetricEncryptor<Key = Zeroizing<Vec<u8>>>
            + SymmetricDecryptor<Key = Zeroizing<Vec<u8>>>,
    {
        // Invalid key size
        let invalid_key = Zeroizing::new(vec![0u8; S::KEY_SIZE - 1]);
        assert!(matches!(
            S::encrypt(&invalid_key, nonce, plaintext, None)
                .unwrap_err()
                .into(),
            Error::Symmetric(SymmetricError::InvalidKeySize)
        ));
        assert!(matches!(
            S::decrypt(&invalid_key, nonce, plaintext, None)
                .unwrap_err()
                .into(),
            Error::Symmetric(SymmetricError::InvalidKeySize)
        ));

        // Invalid nonce size
        let invalid_nonce = vec![0u8; S::NONCE_SIZE - 1];
        assert!(matches!(
            S::encrypt(key, &invalid_nonce, plaintext, None)
                .unwrap_err()
                .into(),
            Error::Symmetric(SymmetricError::InvalidNonceSize)
        ));
        assert!(matches!(
            S::decrypt(key, &invalid_nonce, plaintext, None)
                .unwrap_err()
                .into(),
            Error::Symmetric(SymmetricError::InvalidNonceSize)
        ));
    }

    #[test]
    fn test_aes256gcm_invalid_inputs() {
        let (_, key) = Aes256GcmScheme::generate_keypair().unwrap();
        let nonce = vec![0u8; Aes256GcmScheme::NONCE_SIZE];
        let plaintext = b"test";
        test_invalid_inputs::<Aes256GcmScheme>(&key, &nonce, plaintext);
    }

    #[test]
    fn test_aes128gcm_invalid_inputs() {
        let (_, key) = Aes128GcmScheme::generate_keypair().unwrap();
        let nonce = vec![0u8; Aes128GcmScheme::NONCE_SIZE];
        let plaintext = b"test";
        test_invalid_inputs::<Aes128GcmScheme>(&key, &nonce, plaintext);
    }
} 