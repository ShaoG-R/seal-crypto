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
# seal-crypto = { version = "0.1.0", features = ["rsa", "aes-gcm"] }
```

### 使用示例

以下是一个使用 RSA 进行签名和验证的例子：

```rust
use seal_crypto::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 定义要使用的算法实现
    //    这里我们使用 seal-crypto 内置的 RsaSha256 算法
    use seal_crypto::systems::asymmetric::rsa::RsaSha256;

    // 2. 生成密钥对
    let (public_key, private_key) = RsaSha256::generate_keypair()?;
    println!("成功生成 RSA 密钥对。");

    // 3. 准备消息并签名
    let message = b"This is a very important message.";
    let signature = RsaSha256::sign(&private_key, message)?;
    println!("消息签名成功。");

    // 4. 验证签名
    RsaSha256::verify(&public_key, message, &signature)?;
    println!("签名验证成功！");

    // 尝试用错误的消息进行验证
    let tampered_message = b"This is a tampered message.";
    let verification_result = RsaSha256::verify(&public_key, tampered_message, &signature);
    assert!(verification_result.is_err());
    println!("使用被篡改的消息进行验证，符合预期地失败了。");

    Ok(())
}
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
| **签名** | RSA (SHA-256) | `rsa` |
| **KEM** | RSA | `rsa` |
| | Kyber (PQC) | `kyber` |
| **AEAD** | AES-256-GCM | `aes-gcm` |

## 许可证

本项目采用 Mozilla Public License 2.0 (MPL-2.0) 授权。
详情请见 [LICENSE](./LICENSE) 文件。 