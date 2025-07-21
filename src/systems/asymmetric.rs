//! Entry point for asymmetric algorithm implementations.
//!
//! This module organizes asymmetric cryptographic implementations into two main categories:
//! traditional algorithms that are currently widely used, and post-quantum algorithms
//! that are designed to be secure against quantum computer attacks.
//!
//! # Traditional Algorithms
//! These include well-established algorithms like RSA, ECDSA, and ECDH that are
//! currently considered secure against classical computers but may be vulnerable
//! to sufficiently powerful quantum computers.
//!
//! # Post-Quantum Algorithms
//! These are newer algorithms designed to be secure against both classical and
//! quantum computer attacks. They are being standardized by NIST and other
//! organizations for future use.
//!
//! 非对称算法实现的入口点。
//!
//! 此模块将非对称密码实现组织为两个主要类别：
//! 目前广泛使用的传统算法，以及设计为能够抵抗量子计算机攻击的后量子算法。
//!
//! # 传统算法
//! 这些包括像 RSA、ECDSA 和 ECDH 这样的成熟算法，目前被认为对经典计算机是安全的，
//! 但可能容易受到足够强大的量子计算机的攻击。
//!
//! # 后量子算法
//! 这些是设计为对经典和量子计算机攻击都安全的新算法。
//! 它们正在被 NIST 和其他组织标准化以供未来使用。

/// Post-quantum cryptographic algorithm implementations.
///
/// 后量子密码算法实现。
pub mod post_quantum;

/// Traditional cryptographic algorithm implementations.
///
/// 传统密码算法实现。
pub mod traditional;
