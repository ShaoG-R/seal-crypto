//! Extendable-Output Function (XOF) parameters and implementations.
//!
//! This module provides concrete implementations of XOFs from the SHA-3 family,
//! specifically SHAKE128 and SHAKE256, which can produce variable-length outputs.
//!
//! 可扩展输出函数 (XOF) 参数和实现。
//!
//! 此模块提供了 SHA-3 系列 XOF 的具体实现，
//! 特别是 SHAKE128 和 SHAKE256，它们可以产生可变长度的输出。

/// Re-exports of `sha3` family XOFs with renamed types to avoid conflicts.
///
/// 重新导出 `sha3` 系列 XOF，重命名类型以避免冲突。
pub use sha3::{Shake128 as Shake128_, Shake256 as Shake256_};

use digest::{ExtendableOutput, Update};
use crate::prelude::PrimitiveParams;

mod private {
    pub trait Sealed {}
}

/// A sealed trait representing an Extendable-Output Function (XOF).
///
/// This trait provides a common interface for XOFs that can produce variable-length outputs.
/// It associates a specific `digest::ExtendableOutput` implementation and provides methods
/// for creating XOF readers with input keying material, salt, and context information.
///
/// 一个代表可扩展输出函数 (XOF) 的密封 trait。
///
/// 此 trait 为可产生可变长度输出的 XOF 提供了一个通用接口。
/// 它关联一个具体的 `digest::ExtendableOutput` 实现，并提供了
/// 使用输入密钥材料、盐和上下文信息创建 XOF reader 的方法。
pub trait Xof: private::Sealed + PrimitiveParams {
    /// Creates a new XOF reader with the given inputs.
    ///
    /// # Arguments
    /// * `ikm` - Input keying material.
    /// * `salt` - Optional salt for domain separation.
    /// * `info` - Optional context and application-specific information.
    ///
    /// # Returns
    /// A boxed XOF reader that can produce variable-length output.
    ///
    /// 使用给定的输入创建一个新的 XOF reader。
    ///
    /// # 参数
    /// * `ikm` - 输入密钥材料。
    /// * `salt` - 用于域分离的可选盐。
    /// * `info` - 可选的上下文和应用程序特定信息。
    ///
    /// # 返回
    /// 一个可产生可变长度输出的盒装 XOF reader。
    fn new_xof_reader<'a>(
        ikm: &'a [u8],
        salt: Option<&'a [u8]>,
        info: Option<&'a [u8]>,
    ) -> Box<dyn digest::XofReader + 'a>;
}


/// SHAKE128 extendable-output function implementation.
///
/// SHAKE128 is a member of the SHA-3 family that can produce variable-length outputs.
/// It provides 128 bits of security strength and is suitable for applications requiring
/// flexible output lengths.
///
/// SHAKE128 可扩展输出函数实现。
///
/// SHAKE128 是 SHA-3 系列的成员，可以产生可变长度的输出。
/// 它提供 128 位的安全强度，适用于需要灵活输出长度的应用程序。
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

/// SHAKE256 extendable-output function implementation.
///
/// SHAKE256 is a member of the SHA-3 family that can produce variable-length outputs.
/// It provides 256 bits of security strength and is suitable for applications requiring
/// higher security levels and flexible output lengths.
///
/// SHAKE256 可扩展输出函数实现。
///
/// SHAKE256 是 SHA-3 系列的成员，可以产生可变长度的输出。
/// 它提供 256 位的安全强度，适用于需要更高安全级别和灵活输出长度的应用程序。
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