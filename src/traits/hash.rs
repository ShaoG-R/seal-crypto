//! Defines the core trait for hashing algorithms.
//!
//! 定义了哈希算法的核心 trait。
#[cfg(feature = "digest")]
use digest::{Digest, DynDigest, ExtendableOutput, FixedOutputReset, Update};
#[cfg(feature = "digest")]
mod private {
    pub trait Sealed {}
}

/// A sealed trait representing a hash function.
/// It associates a specific `digest::Digest` implementation.
///
/// 一个代表哈希函数的密封 trait。
/// 它关联一个具体的 `digest::Digest` 实现。
#[cfg(feature = "digest")]
pub trait Hasher: private::Sealed + Send + Sync + 'static {
    /// The actual digest implementation from the `digest` crate.
    ///
    /// 来自 `digest` crate 的实际摘要实现。
    type Digest: Digest + Clone + Send + Sync + 'static + FixedOutputReset + DynDigest;

    /// The name of the hash function.
    ///
    /// 哈希函数的名称。
    const NAME: &'static str;
    /// The unique offset for the hash function's ID.
    ///
    /// 哈希函数ID的唯一偏移量。
    const ID_OFFSET: u32;
}

/// `sha2` family hash functions
#[cfg(feature = "sha2")]
pub use sha2::{Sha256 as Sha256_, Sha384 as Sha384_, Sha512 as Sha512_};

#[cfg(feature = "sha2")]
pub struct Sha256;

#[cfg(feature = "sha2")]
impl private::Sealed for Sha256 {}

#[cfg(feature = "sha2")]
impl Hasher for Sha256 {
    type Digest = Sha256_;
    const NAME: &'static str = "SHA-256";
    const ID_OFFSET: u32 = 1;
}

#[cfg(feature = "sha2")]
pub struct Sha384;

#[cfg(feature = "sha2")]
impl private::Sealed for Sha384 {}

#[cfg(feature = "sha2")]
impl Hasher for Sha384 {
    type Digest = Sha384_;
    const NAME: &'static str = "SHA-384";
    const ID_OFFSET: u32 = 2;
}

#[cfg(feature = "sha2")]
pub struct Sha512;

#[cfg(feature = "sha2")]
impl private::Sealed for Sha512 {}

#[cfg(feature = "sha2")]
impl Hasher for Sha512 {
    type Digest = Sha512_;
    const NAME: &'static str = "SHA-512";
    const ID_OFFSET: u32 = 3;
}

/// A sealed trait representing an Extendable-Output Function (XOF).
/// It associates a specific `digest::ExtendableOutput` implementation.
///
/// 一个代表可扩展输出函数 (XOF) 的密封 trait。
/// 它关联一个具体的 `digest::ExtendableOutput` 实现。
#[cfg(feature = "digest")]
pub trait Xof: private::Sealed + Send + Sync + 'static + Default {
    /// The actual XOF implementation from the `digest` crate.
    ///
    /// 来自 `digest` crate 的实际 XOF 实现。
    type Xof: ExtendableOutput + Clone + Send + Sync + 'static + Update + Default;
    /// The name of the XOF.
    ///
    /// XOF 的名称。
    const NAME: &'static str;
    /// The unique offset for the XOF's ID.
    ///
    /// XOF ID的唯一偏移量。
    const ID_OFFSET: u32;
}

/// `sha3` family hash functions
#[cfg(feature = "shake-default")]
pub use sha3::{Shake128 as Shake128_, Shake256 as Shake256_};

#[cfg(feature = "shake-default")]
#[derive(Default)]
pub struct Shake128;

#[cfg(feature = "shake-default")]
impl private::Sealed for Shake128 {}

#[cfg(feature = "shake-default")]
impl Xof for Shake128 {
    type Xof = Shake128_;
    const NAME: &'static str = "SHAKE128";
    const ID_OFFSET: u32 = 1;
}

#[cfg(feature = "shake-default")]
#[derive(Default)]
pub struct Shake256;

#[cfg(feature = "shake-default")]
impl private::Sealed for Shake256 {}

#[cfg(feature = "shake-default")]
impl Xof for Shake256 {
    type Xof = Shake256_;
    const NAME: &'static str = "SHAKE256";
    const ID_OFFSET: u32 = 2;
}
