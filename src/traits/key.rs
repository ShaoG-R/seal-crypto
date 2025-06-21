//! Defines the core trait for key generation.
//!
//! 定义了密钥生成的核心 trait。
use zeroize::Zeroizing;
use crate::errors::Error;

/// Represents a generic public key.
///
/// 代表一个通用的公钥。
pub type PublicKey = Vec<u8>;

/// Represents a generic private key, which will be zeroized on drop.
///
/// 代表一个通用的私钥，它在被丢弃时将被清零。
pub type PrivateKey = Zeroizing<Vec<u8>>;

/// A trait for cryptographic schemes that can generate key pairs.
///
/// 用于可生成密钥对的加密方案的 trait。
pub trait KeyGenerator {

    /// Generates a new key pair.
    ///
    /// The `config` parameter is currently a placeholder and not used,
    /// allowing for future extensions where generation might be configurable
    /// (e.g., specifying key size).
    ///
    /// 生成一个新的密钥对。
    ///
    /// `config` 参数当前是一个占位符并未使用，
    /// 以便未来进行扩展，使密钥生成过程可以配置
    /// （例如，指定密钥大小）。
    fn generate_keypair() -> Result<(PublicKey, PrivateKey), Error>;
} 