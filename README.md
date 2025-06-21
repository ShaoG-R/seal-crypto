# seal-crypto

[![Crates.io](https://img.shields.io/crates/v/seal-crypto.svg)](https://crates.io/crates/seal-crypto)
[![Docs.rs](https://docs.rs/seal-crypto/badge.svg)](https://docs.rs/seal-crypto)
[![License](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](./LICENSE)

`seal-crypto` is the underlying cryptographic engine for the `seal-kit` ecosystem, providing a set of pure, trait-based cryptographic capability abstractions and implementations.

[中文文档 (Chinese Version)](README_CN.md)

## Core Philosophy

`seal-crypto` is designed to be clear, modern, and aligned with Rust API best practices. Its core principles are:

1.  **Trait-Based Abstraction**: The library is built around a set of traits that define fundamental cryptographic operations (e.g., encryption, signing, key generation). This approach cleanly separates the interface (what you want to do) from the implementation (how it's done).
2.  **Modular & Composable**: Specific cryptographic algorithms (like AES, RSA, Kyber) are implemented as independent units that fulfill these traits. Users can enable only the algorithms they need via Cargo features, resulting in a smaller, more focused application.
3.  **Security-First**:
    *   **Memory Safety**: All sensitive data, such as `PrivateKey`, `SymmetricKey`, and `SharedSecret`, are wrapped using the [`zeroize`](https://crates.io/crates/zeroize) crate. This ensures that the memory they occupy is securely wiped when they go out of scope, significantly reducing the risk of key material leakage.
    *   **Explicit Error Handling**: Each cryptographic domain has its own specific, descriptive error types (e.g., `SignatureError`, `KemError`) to allow for clear and robust error handling.
4.  **Ease of Use**: A `prelude` module is provided. A simple `use seal_crypto::prelude::*` brings all essential traits and types into scope, streamlining development.

## Quick Start

Add `seal-crypto` to your `Cargo.toml`. You can enable the `full` feature to include all supported algorithms, or select individual algorithm features as needed.

```toml
[dependencies]
# Enable all features
seal-crypto = { version = "0.1.0", features = ["full"] }

# Or, enable only specific algorithms
# seal-crypto = { version = "0.1.0", features = ["rsa", "aes-gcm"] }
```

### Example Usage

Here is an example of signing and verifying a message using RSA:

```rust
use seal_crypto::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Define the algorithm implementation to use.
    //    Here, we use the built-in RsaSha256 implementation.
    use seal_crypto::systems::asymmetric::rsa::RsaSha256;

    // 2. Generate a key pair.
    let (public_key, private_key) = RsaSha256::generate_keypair()?;
    println!("Successfully generated RSA key pair.");

    // 3. Prepare a message and sign it.
    let message = b"This is a very important message.";
    let signature = RsaSha256::sign(&private_key, message)?;
    println!("Message signed successfully.");

    // 4. Verify the signature.
    RsaSha256::verify(&public_key, message, &signature)?;
    println!("Signature verification successful!");

    // 5. Attempt to verify with a tampered message.
    let tampered_message = b"This is a tampered message.";
    let verification_result = RsaSha256::verify(&public_key, tampered_message, &signature);
    assert!(verification_result.is_err());
    println!("Verification with tampered message failed as expected.");

    Ok(())
}
```

## Supported Algorithms

| Capability | Algorithm | Cargo Feature |
| :--- | :--- | :--- |
| **Signature** | RSA (SHA-256) | `rsa` |
| **KEM** | RSA | `rsa` |
| | Kyber (PQC) | `kyber` |
| **AEAD** | AES-256-GCM | `aes-gcm` |

## License

This project is licensed under the Mozilla Public License 2.0 (MPL-2.0).
See the [LICENSE](./LICENSE) file for details. 