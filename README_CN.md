# seal-crypto

[![Crates.io](https://img.shields.io/crates/v/seal-crypto.svg)](https://crates.io/crates/seal-crypto)
[![Docs.rs](https://docs.rs/seal-crypto/badge.svg)](https://docs.rs/seal-crypto)
[![License](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](./LICENSE)

`seal-crypto` 是 `seal-kit` 生态系统的底层加密引擎，提供了一套纯粹的、基于 Trait 的加密能力抽象和实现。

[English Version](README.md)

## 设计理念

`seal-crypto` 的设计清晰、现代化，并遵循了 Rust API 设计的最佳实践。其核心理念可以概括为以下几点：

1.  **基于 Trait 的抽象**: 库的核心是围绕一组定义了基本加密操作（如加密、签名、密钥生成）的 `trait` 构建的。这种方法将接口（你想要做什么）与实现（具体用哪种算法做）完全分离。
2.  **模块化和可组合性**: 具体的加密算法（如 AES, RSA, Kyber）作为独立的单元实现这些 `trait`。用户可以通过 Cargo 的 features 来选择性地启用他们需要的算法，从而使最终的程序更小、更专注。
3.  **安全优先**:
    *   **内存安全**: 所有敏感数据，如私钥（`PrivateKey`）、对称密钥（`SymmetricKey`）和共享密钥（`SharedSecret`），都使用 [`zeroize`](https://crates.io/crates/zeroize) 库进行包装。这意味着当这些密钥离开其作用域时，它们占用的内存会被安全地擦除，极大地降低了密钥泄露的风险。
    *   **明确的错误处理**: 每种加密操作都有其专属的、详细的错误类型（如 `SignatureError`, `KemError`），让调用者可以清晰地处理失败情况。
4.  **易用性**: 提供了一个 `prelude` 模块，只需 `use seal_crypto::prelude::*` 就可以方便地导入所有核心的 trait 和类型，简化了开发体验。

## 快速开始

将 `seal-crypto` 添加到你的 `Cargo.toml` 中。你可以启用 `full` 功能来包含所有支持的算法，或者根据需要选择独立的算法功能。

```toml
[dependencies]
# 启用所有功能
seal-crypto = { version = "0.1.0", features = ["full"] }

# 或者，只启用特定算法
# seal-crypto = { version = "0.1.0", features = ["rsa", "aes-gcm", "kyber"] }
```

### 使用示例

以下是一个使用 RSA-4096 进行签名和验证的快速示例：

```rust
use seal_crypto::prelude::*;
use seal_crypto::systems::asymmetric::rsa::{Rsa4096, RsaScheme};

fn main() -> Result<(), CryptoError> {
    // 1. 使用 RsaScheme 和 Rsa4096 参数来生成密钥对。
    let (public_key, private_key) = RsaScheme::<Rsa4096>::generate_keypair()?;
    println!("成功生成 RSA-4096 密钥对。");

    // 2. 准备消息并签名。
    let message = b"这是一条重要的消息。";
    let signature = RsaScheme::<Rsa4096>::sign(&private_key, message)?;
    println!("消息签名成功。");

    // 3. 验证签名。
    RsaScheme::<Rsa4096>::verify(&public_key, message, &signature)?;
    println!("签名验证成功！");

    Ok(())
}
```

我们提供了更详细的示例代码，请查看 `examples` 目录。你可以使用 `cargo` 来运行它们：

```sh
# 运行混合加密示例
cargo run --example hybrid_encryption --features "full"

# 运行数字签名示例
cargo run --example digital_signature --features "full"
```

## API 概览

API 主要由以下几个核心 `trait` 组成，它们位于 `seal_crypto::traits` 模块下：

-   `KeyGenerator`: 为非对称加密算法生成密钥对。
-   `SymmetricEncryptor` / `SymmetricDecryptor`: 提供对称认证加密（AEAD）功能。
-   `Kem` (Key Encapsulation Mechanism): 用于安全地交换密钥。
-   `Signer` / `Verifier`: 创建和验证数字签名。

## 支持的算法

| 功能 | 算法 | Cargo Feature |
| :--- | :--- | :--- |
| **签名** | RSA-PSS (2048/4096 位) | `rsa` |
| **KEM** | RSA-OAEP (2048/4096 位) | `rsa` |
| | Kyber (512/768/1024) | `kyber` |
| **AEAD** | AES-GCM (128/256 位) | `aes-gcm` |

## 许可证

本项目采用 Mozilla Public License 2.0 (MPL-2.0) 授权。
详情请见 [LICENSE](./LICENSE) 文件。 