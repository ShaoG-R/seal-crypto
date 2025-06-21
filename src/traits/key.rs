//! Defines the core trait for key generation.
use zeroize::Zeroizing;
use crate::errors::Error;

/// Represents a generic public key.
pub type PublicKey = Vec<u8>;

/// Represents a generic private key, which will be zeroized on drop.
pub type PrivateKey = Zeroizing<Vec<u8>>;

/// A trait for cryptographic schemes that can generate key pairs.
pub trait KeyGenerator {

    /// Generates a new key pair.
    ///
    /// The `config` parameter is currently a placeholder and not used,
    /// allowing for future extensions where generation might be configurable
    /// (e.g., specifying key size).
    fn generate_keypair() -> Result<(PublicKey, PrivateKey), Error>;
} 