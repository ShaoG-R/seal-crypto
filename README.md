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
# seal-crypto = { version = "0.1.0", features = ["rsa", "aes-gcm", "kyber"] }
```

### Example Usage

Here is a quick example of signing and verifying a message using RSA-4096 with SHA-256.

```rust
use seal_crypto::prelude::*;
use seal_crypto::schemes::asymmetric::traditional::rsa::Rsa4096;
// use seal_crypto::schemes::hash::Sha256;

fn main() -> Result<(), CryptoError> {
    // 1. Define the scheme by key parameters.
    // By default, RsaScheme uses Sha256 as the hash function.
    type MyRsaScheme = Rsa4096;

    // 2. Generate a key pair.
    let (public_key, private_key) = MyRsaScheme::generate_keypair()?;
    println!("Successfully generated RSA-4096 key pair.");

    // 3. Prepare a message and sign it.
    let message = b"This is an important message.";
    let signature = MyRsaScheme::sign(&private_key, message)?;
    println!("Message signed successfully.");

    // 4. Verify the signature.
    MyRsaScheme::verify(&public_key, message, &signature)?;
    println!("Signature verification successful!");

    Ok(())
}
```

For more detailed examples, check out the `examples` directory. You can run them using `cargo`:

```sh
# Run the hybrid encryption example
cargo run --example hybrid_encryption --features "full"

# Run the digital signature example
cargo run --example digital_signature --features "full"
```

## Trait Design Philosophy

The power and clarity of `seal-crypto` come from its layered, consistent, and single-responsibility trait architecture. This design makes the library both easy to use for common tasks and flexible enough for advanced generic programming.

The hierarchy can be visualized as follows:

```mermaid
graph TD
    subgraph "Top Layer: Algorithm Identity"
        Z["Algorithm<br/><i>The top-level trait for all schemes,<br/>provides a 'NAME' constant.</i>"]
    end

    subgraph "Base Layer: Key Primitives"
        A["Key<br/><i>Defines basic key behaviors like serialization.</i>"]
        B["PublicKey / PrivateKey<br/><i>Marker traits for key types.</i>"]
    end

    subgraph "Layer 1: KeySet - The Single Source of Truth"
        C["AsymmetricKeySet<br/><i>Inherits Algorithm<br/><b>- type PublicKey<br/>- type PrivateKey</b></i>"]
        D["SymmetricKeySet<br/><i>Inherits Algorithm<br/><b>- type Key</b></i>"]
    end

    subgraph "Layer 2: Capabilities"
        F["KeyGenerator<br/><i>Inherits AsymmetricKeySet,<br/>adds 'generate_keypair'.</i>"]
        G["Signer / Verifier<br/><i>Inherit AsymmetricKeySet,<br/>add 'sign'/'verify'.</i>"]
        H["Kem<br/><i>Inherits AsymmetricKeySet,<br/>adds 'encapsulate'/'decapsulate'.</i>"]
        M["KeyAgreement<br/><i>Inherits AsymmetricKeySet,<br/>adds 'agree'.</i>"]
        I["SymmetricKeyGenerator<br/><i>Inherits SymmetricKeySet,<br/>adds 'generate_key'.</i>"]
        J["SymmetricEncryptor / Decryptor<br/><i>Inherit SymmetricKeySet,<br/>add 'encrypt'/'decrypt'.</i>"]
        
        subgraph "Derivation"
            N_BASE["Derivation<br/><i>Top-level trait for derivation</i>"]
            N_KEY["KeyBasedDerivation<br/><i>For high-entropy keys</i>"]
            N_PASS["PasswordBasedDerivation<br/><i>For low-entropy passwords</i>"]
        end
    end
    
    subgraph "Layer 3: Scheme Bundles (for convenience)"
        K["SignatureScheme<br/><i>Bundles KeyGenerator, Signer, Verifier.</i>"]
        L["AeadScheme<br/><i>Bundles SymmetricKeySet, SymmetricKeyGenerator, etc.</i>"]
    end

    A --> B

    Z --> C
    Z --> D
    Z --> N_BASE
    
    C --> F
    C --> G
    C --> H
    C --> M
    
    F & G --> K

    D --> I
    D --> J
    I & J --> L

    N_BASE --> N_KEY
    N_BASE --> N_PASS
end
```

Here's a breakdown of the layers:

1.  **Top Layer: Algorithm Identity (`Algorithm`)**: This is the unified top-level trait for all cryptographic schemes (both symmetric and asymmetric). It defines a single `NAME` constant to provide a unique, readable identifier for each algorithm (e.g., "RSA-PSS-SHA256").
2.  **Base Layer: Key Primitives (`Key`)**: At the very bottom are fundamental traits like `Key`, `PublicKey`, and `PrivateKey`. They define the absolute basic properties of any key, such as serialization.
3.  **Layer 1: The KeySet**: This is the core of the design. `AsymmetricKeySet` and `SymmetricKeySet` inherit from `Algorithm` and have a single responsibility: to define the associated key types for a cryptographic scheme. They are the **single source of truth** for `PublicKey`, `PrivateKey`, and `SymmetricKey`.
4.  **Layer 2: Capabilities**: This layer defines actions. Traits like `KeyGenerator`, `Signer`, `Kem`, `KeyAgreement`, and `SymmetricEncryptor` inherit directly from their respective KeySet layer and add specific methods (`generate_keypair`, `sign`, `encapsulate`, `agree`, etc.). They define *what you can do* with a scheme.
5.  **Layer 3: Scheme Bundles**: For user convenience, we provide "supertraits" like `SignatureScheme` and `AeadScheme`. They don't add new methods but bundle all relevant capabilities into a single, easy-to-use trait.

This layered approach ensures that every trait has a clear purpose, preventing ambiguity and making the entire library highly consistent and predictable.

## Supported Algorithms

| Capability | Algorithm | Cargo Feature |
| :--- | :--- | :--- |
| **Signature** | RSA-PSS (2048/4096 bits, configurable hash) | `rsa`, `sha2`, etc. |
| | ECDSA (P-256) | `ecc` |
| | EdDSA (Ed25519) | `ecc` |
| | Dilithium (2/3/5) | `dilithium` |
| **KEM** | RSA-OAEP (2048/4096 bits, configurable hash) | `rsa`, `sha2`, etc. |
| | Kyber (512/768/1024) | `kyber` |
| **Key Agreement** | ECDH (P-256) | `ecdh` |
| **AEAD** | AES-GCM (128/256 bits) | `aes-gcm` |
| | ChaCha20-Poly1305 | `chacha20-poly1305` |
| **Key Derivation (KDF)** | HKDF (SHA-256, SHA-384, SHA-512) | `hkdf` |
| **Password Derivation (PBKDF)** | PBKDF2 (SHA-256, SHA-384, SHA-512) | `pbkdf2` |
| **Hashing** | SHA-2 (256, 384, 512) | `sha2` |

## License

This project is licensed under the Mozilla Public License 2.0 (MPL-2.0).
See the [LICENSE](./LICENSE) file for details. 