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
    /// Creates a new XOF reader with the given inputs.
    ///
    /// 使用给定的输入创建一个新的 XOF reader。
    fn new_xof_reader<'a>(
        ikm: &'a [u8],
        salt: Option<&'a [u8]>,
        info: Option<&'a [u8]>,
    ) -> Box<dyn digest::XofReader + 'a>;
}


#[derive(Clone, Default, Debug)]
pub struct Shake128;

impl private::Sealed for Shake128 {}

impl PrimitiveParams for Shake128 {
    const NAME: &'static str = "SHAKE128";
    const ID_OFFSET: u32 = 1;
}

impl Xof for Shake128 {
    fn new_xof_reader<'a>(
        ikm: &'a [u8],
        salt: Option<&'a [u8]>,
        info: Option<&'a [u8]>,
    ) -> Box<dyn digest::XofReader + 'a> {
        let mut xof = Shake128_::default();
        if let Some(s) = salt {
            xof.update(s);
        }
        xof.update(ikm);
        if let Some(i) = info {
            xof.update(i);
        }
        Box::new(xof.finalize_xof())
    }
}

#[derive(Clone, Default, Debug)]
pub struct Shake256;

impl private::Sealed for Shake256 {}

impl PrimitiveParams for Shake256 {
    const NAME: &'static str = "SHAKE256";
    const ID_OFFSET: u32 = 2;
}

impl Xof for Shake256 {
    fn new_xof_reader<'a>(
        ikm: &'a [u8],
        salt: Option<&'a [u8]>,
        info: Option<&'a [u8]>,
    ) -> Box<dyn digest::XofReader + 'a> {
        let mut xof = Shake256_::default();
        if let Some(s) = salt {
            xof.update(s);
        }
        xof.update(ikm);
        if let Some(i) = info {
            xof.update(i);
        }
        Box::new(xof.finalize_xof())
    }
}