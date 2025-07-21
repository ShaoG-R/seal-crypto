/// `sha2` family hash functions
pub use sha2::{Sha256 as Sha256_, Sha384 as Sha384_, Sha512 as Sha512_};

use digest::{Digest, DynDigest, FixedOutputReset};
use crate::prelude::PrimitiveParams;

mod private {
    pub trait Sealed {}
}

/// A sealed trait representing a hash function.
/// It associates a specific `digest::Digest` implementation.
///
/// 一个代表哈希函数的密封 trait。
/// 它关联一个具体的 `digest::Digest` 实现。
pub trait Hasher:
    private::Sealed + PrimitiveParams
{
    /// The actual digest implementation from the `digest` crate.
    ///
    /// 来自 `digest` crate 的实际摘要实现。
    type Digest: Digest + Clone + Send + Sync + 'static + FixedOutputReset + DynDigest;
}

#[derive(Clone, Default, Debug)]
pub struct Sha256;

impl private::Sealed for Sha256 {}

impl PrimitiveParams for Sha256 {
    const NAME: &'static str = "SHA-256";
    const ID_OFFSET: u32 = 1;
}

impl Hasher for Sha256 {
    type Digest = Sha256_;
}

#[derive(Clone, Default, Debug)]
pub struct Sha384;

impl private::Sealed for Sha384 {}

impl PrimitiveParams for Sha384 {
    const NAME: &'static str = "SHA-384";
    const ID_OFFSET: u32 = 2;
}

impl Hasher for Sha384 {
    type Digest = Sha384_;
}

#[derive(Clone, Default, Debug)]
pub struct Sha512;

impl private::Sealed for Sha512 {}

impl PrimitiveParams for Sha512 {
    const NAME: &'static str = "SHA-512";
    const ID_OFFSET: u32 = 3;
}

impl Hasher for Sha512 {
    type Digest = Sha512_;
}