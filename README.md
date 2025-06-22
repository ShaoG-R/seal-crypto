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
use seal_cryptos::asymmetric::rsa::{Rsa4096, RsaScheme};
// use seal_cryptos::hash::Sha256;

fn main() -> Result<(), CryptoError> {
    // 1. Define the scheme by key parameters.
    // By default, RsaScheme uses Sha256 as the hash function.
    type MyRsaScheme = RsaScheme<Rsa4096>;

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
    subgraph "Base Layer: Key Primitives"
        A[Key<br/><i>Defines basic key behaviors like serialization.</i>]
        B[PublicKey / PrivateKey<br/><i>Marker traits for key types.</i>]
    end

    subgraph "Layer 1: KeySet - The Single Source of Truth"
        C[AsymmetricKeySet<br/><b>- type PublicKey<br/>- type PrivateKey</b>]
        D[SymmetricKeySet<br/><b>- type Key</b>]
    end

    subgraph "Layer 2: Capabilities"
        E[Algorithm<br/><i>Inherits AsymmetricKeySet,<br/>adds `NAME` constant.</i>]
        F[KeyGenerator<br/><i>Inherits Algorithm,<br/>adds `generate_keypair`.</i>]
        G[Signer / Verifier<br/><i>Inherit Algorithm,<br/>add `sign`/`verify`.</i>]
        H[Kem<br/><i>Inherits Algorithm,<br/>adds `encapsulate`/`decapsulate`.</i>]
        I[SymmetricKeyGenerator<br/><i>Inherits SymmetricKeySet,<br/>adds `generate_key`.</i>]
        J[SymmetricEncryptor / Decryptor<br/><i>Inherit SymmetricKeySet,<br/>add `encrypt`/`decrypt`.</i>]
    end
    
    subgraph "Layer 3: Scheme Bundles (for convenience)"
        K[SignatureScheme<br/><i>Bundles Algorithm, KeyGenerator, Signer, Verifier.</i>]
        L[AeadScheme<br/><i>Bundles SymmetricKeySet, SymmetricKeyGenerator, etc.</i>]
    end

    A --> B
    C --> E --> F
    E --> G
    E --> H
    F & G --> K

    D --> I
    D --> J
    I & J --> L
```

Here's a breakdown of the layers:

1.  **Base Layer: Key Primitives**: At the very bottom are fundamental traits like `Key`, `PublicKey`, and `PrivateKey`. They define the absolute basic properties of any key.
2.  **Layer 1: The KeySet**: This is the core of the design. `AsymmetricKeySet` and `SymmetricKeySet` have a single responsibility: to define the associated key types for a cryptographic scheme. They are the **single source of truth** for `PublicKey`, `PrivateKey`, and `SymmetricKey`.
3.  **Layer 2: Capabilities**: This layer defines actions. Traits like `KeyGenerator`, `Signer`, `Kem`, and `SymmetricEncryptor` inherit from the KeySet layer and add specific methods (`generate_keypair`, `sign`, `encapsulate`, etc.). They define *what you can do* with a scheme.
4.  **Layer 3: Scheme Bundles**: For user convenience, we provide "supertraits" like `SignatureScheme` and `AeadScheme`. They don't add new methods but bundle all relevant capabilities into a single, easy-to-use trait.

This layered approach ensures that every trait has a clear purpose, preventing ambiguity and making the entire library highly consistent and predictable.

## Supported Algorithms

| Capability | Algorithm | Cargo Feature |
| :--- | :--- | :--- |
| **Signature** | RSA-PSS (2048/4096 bits, configurable hash) | `rsa`, `sha256`, etc. |
| **KEM** | RSA-OAEP (2048/4096 bits, configurable hash) | `rsa`, `sha256`, etc. |
| | Kyber (512/768/1024) | `kyber` |
| **AEAD** | AES-GCM (128/256 bits) | `aes-gcm` |
| | ChaCha20-Poly1305 | `chacha20-poly1305` |
| **Hashing** | SHA-2 (256, 384, 512) | `sha256`, `sha384`, `sha512` |

## License

This project is licensed under the Mozilla Public License 2.0 (MPL-2.0).
See the [LICENSE](./LICENSE) file for details. 