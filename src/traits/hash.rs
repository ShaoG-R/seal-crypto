//! Defines the core trait for hashing algorithms.
//!
//! 定义了哈希算法的核心 trait。

use digest::{Digest, DynDigest, FixedOutputReset};

mod private {
    pub trait Sealed {}
}

/// A sealed trait representing a hash function.
/// It associates a specific `digest::Digest` implementation.
///
/// 一个代表哈希函数的密封 trait。
/// 它关联一个具体的 `digest::Digest` 实现。
pub trait Hasher: private::Sealed + Send + Sync + 'static {
    /// The actual digest implementation from the `digest` crate.
    ///
    /// 来自 `digest` crate 的实际摘要实现。
    type Digest: Digest + Clone + Send + Sync + 'static + FixedOutputReset + DynDigest;
}

// --- Marker Structs for common hash functions ---

/// Marker struct for SHA-256.
#[cfg(feature = "sha256")]
#[derive(Debug, Default)]
pub struct Sha256;

#[cfg(feature = "sha256")]
impl private::Sealed for Sha256 {}

#[cfg(feature = "sha256")]
impl Hasher for Sha256 {
    type Digest = sha2::Sha256;
}

/// Marker struct for SHA-384.
#[cfg(feature = "sha384")]
#[derive(Debug, Default)]
pub struct Sha384;

#[cfg(feature = "sha384")]
impl private::Sealed for Sha384 {}

#[cfg(feature = "sha384")]
impl Hasher for Sha384 {
    type Digest = sha2::Sha384;
}

/// Marker struct for SHA-512.
#[cfg(feature = "sha512")]
#[derive(Debug, Default)]
pub struct Sha512;

#[cfg(feature = "sha512")]
impl private::Sealed for Sha512 {}

#[cfg(feature = "sha512")]
impl Hasher for Sha512 {
    type Digest = sha2::Sha512;
}
