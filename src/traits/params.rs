//! Defines a core trait for cryptographic scheme parameters.
//!
//! 定义了密码学方案参数的核心 trait。
#[cfg(feature = "sha2")]
pub mod hash;
#[cfg(feature = "shake-default")]
pub mod xof;

#[cfg(feature = "sha2")]
pub use hash::*;
#[cfg(feature = "shake-default")]
pub use xof::*;

/// A common trait for cryptographic scheme parameters.
///
/// This trait provides a common interface for defining the basic properties of a cryptographic scheme,
/// such as its name and a unique identifier. It is intended to be implemented by marker structs
/// that represent a specific parameter set for a cryptographic algorithm.
///
/// 密码学方案参数的通用 trait。
///
/// 此 trait 为定义密码学方案的基本属性（如其名称和唯一标识符）提供了一个通用接口。
/// 它旨在由代表特定密码算法参数集的标记结构体来实现。
pub trait SchemeParams: Send + Sync + 'static + Clone + Default + std::fmt::Debug {
    /// The unique name of the algorithm (e.g., "AES-128-GCM").
    ///
    /// 算法的唯一名称 (例如, "AES-128-GCM")。
    const NAME: &'static str;

    /// The unique ID for the scheme, used for serialization and identification.
    ///
    /// 方案的唯一ID，用于序列化和识别。
    const ID: u32;
}

/// An enum to represent different types of parameter values for introspection.
///
/// 一个枚举，用于表示用于内省的不同类型的参数值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamValue {
    U32(u32),
    String(String),
}

/// A trait for schemes that have configurable parameters, either at the type level or instance level.
///
/// This trait allows for runtime introspection of a scheme's full parameter set.
///
/// 一个用于在类型级别或实例级别具有可配置参数的方案的 trait。
///
/// 此 trait 允许对方案的完整参数集进行运行时内省。
pub trait Parameterized {
    /// Returns a list of parameters defined at the type level (e.g., generic parameters).
    ///
    /// 返回在类型级别定义的参数列表（例如，泛型参数）。
    fn get_type_params() -> Vec<(&'static str, ParamValue)>
    where
        Self: Sized;

    /// Returns a list of parameters specific to this instance (e.g., fields of the struct).
    ///
    /// 返回特定于此实例的参数列表（例如，结构体的字段）。
    fn get_instance_params(&self) -> Vec<(&'static str, ParamValue)>;
}

/// A trait for cryptographic primitives like hash functions and XOFs.
///
/// This trait provides a common interface for defining the basic properties of a primitive,
/// such as its name and a unique identifier offset.
///
/// 用于密码学原语（如哈希函数和XOF）的 trait。
///
/// 此 trait 为定义原语的基本属性（如其名称和唯一的标识符偏移量）提供了一个通用接口。
pub trait PrimitiveParams: Send + Sync + 'static + Clone + Default + std::fmt::Debug {
    /// The name of the primitive (e.g., "SHA-256").
    ///
    /// 原语的名称（例如，"SHA-256"）。
    const NAME: &'static str;

    /// The unique offset for the primitive's ID. This is used to calculate the final
    /// algorithm ID when the primitive is used within a larger scheme.
    ///
    /// 原语ID的唯一偏移量。当原语在更大的方案中使用时，此偏移量用于计算最终的算法ID。
    const ID_OFFSET: u32;
}
