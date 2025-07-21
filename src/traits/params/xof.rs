pub use sha3::{Shake128 as Shake128_, Shake256 as Shake256_};

use digest::{ExtendableOutput, Update};
use crate::prelude::PrimitiveParams;

mod private {
    pub trait Sealed {}
}

/// A sealed trait representing an Extendable-Output Function (XOF).
/// It associates a specific `digest::ExtendableOutput` implementation.
///
/// 一个代表可扩展输出函数 (XOF) 的密封 trait。
/// 它关联一个具体的 `digest::ExtendableOutput` 实现。
pub trait Xof: private::Sealed + PrimitiveParams {
    /// The actual XOF implementation from the `digest` crate.
    ///
    /// 来自 `digest` crate 的实际 XOF 实现。
    type Xof: ExtendableOutput + Send + Sync + 'static + Update + Default;
}


#[derive(Clone, Default, Debug)]
pub struct Shake128;

impl private::Sealed for Shake128 {}

impl PrimitiveParams for Shake128 {
    const NAME: &'static str = "SHAKE128";
    const ID_OFFSET: u32 = 1;
}

impl Xof for Shake128 {
    type Xof = Shake128_;
}

#[derive(Clone, Default, Debug)]
pub struct Shake256;

impl private::Sealed for Shake256 {}

impl PrimitiveParams for Shake256 {
    const NAME: &'static str = "SHAKE256";
    const ID_OFFSET: u32 = 2;
}

impl Xof for Shake256 {
    type Xof = Shake256_;
}