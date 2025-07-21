//! Defines traits for extendable-output functions (XOFs).
//!
//! 定义了可扩展输出函数 (XOF) 的 trait。
#[cfg(feature = "digest")]
use crate::{errors::Error, prelude::Derivation};

#[cfg(feature = "digest")]
use digest::XofReader as DigestXofReader;

/// A reader for extendable-output functions (XOFs).
///
/// This struct wraps a boxed `digest::XofReader` to provide a concrete type
/// that can be returned from trait methods.
///
/// 可扩展输出函数 (XOF) 的读取器。
///
/// 此结构体包装了一个盒装的 `digest::XofReader`，以提供可从 trait 方法返回的具体类型。
#[cfg(feature = "digest")]
pub struct XofReader<'a> {
    reader: Box<dyn DigestXofReader + 'a>,
}

#[cfg(feature = "digest")]
impl<'a> XofReader<'a> {
    /// Creates a new `XofReader` from a boxed `digest::XofReader`.
    ///
    /// 从盒装的 `digest::XofReader` 创建一个新的 `XofReader`。
    pub fn new<R: DigestXofReader + 'a>(reader: R) -> Self {
        Self {
            reader: Box::new(reader),
        }
    }

    /// Creates a new `XofReader` from an already boxed `digest::XofReader`.
    ///
    /// 从一个已经盒装的 `digest::XofReader` 创建一个新的 `XofReader`。
    pub fn from_boxed(reader: Box<dyn DigestXofReader + 'a>) -> Self {
        Self { reader }
    }
}

#[cfg(feature = "digest")]
impl<'a> DigestXofReader for XofReader<'a> {
    fn read(&mut self, buffer: &mut [u8]) {
        self.reader.read(buffer);
    }

    fn read_boxed(&mut self, n: usize) -> Box<[u8]> {
        self.reader.read_boxed(n)
    }
}

/// A trait for Key Derivation Functions based on Extendable-Output Functions (XOFs).
///
/// This trait allows for deriving a stream of bytes from Input Keying Material (IKM),
/// which is useful for generating multiple keys or keys of a length not known beforehand.
///
/// 基于可扩展输出函数 (XOF) 的密钥派生函数 trait。
///
/// 此 trait 允许从输入密钥材料 (IKM) 派生字节流，
/// 这对于生成多个密钥或预先未知长度的密钥非常有用。
#[cfg(feature = "digest")]
pub trait XofDerivation: Derivation {
    /// Derives a byte stream from Input Keying Material (IKM).
    ///
    /// # Arguments
    /// * `ikm` - The Input Keying Material.
    /// * `salt` - An optional salt.
    /// * `info` - Optional context and application-specific information.
    ///
    /// # Returns
    /// An `XofReader` that can be used to read an arbitrary number of bytes.
    ///
    /// 从输入密钥材料 (IKM) 派生字节流。
    ///
    /// # 参数
    /// * `ikm` - 输入密钥材料。
    /// * `salt` - 可选的盐。
    /// * `info` - 可选的上下文和应用程序特定信息。
    ///
    /// # 返回
    /// 一个可用于读取任意数量字节的 `XofReader`。
    fn reader<'a>(
        &self,
        ikm: &'a [u8],
        salt: Option<&'a [u8]>,
        info: Option<&'a [u8]>,
    ) -> Result<XofReader<'a>, Error>;
}
