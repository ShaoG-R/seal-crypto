//! An example demonstrating the SHAKE Extendable-Output Function (XOF).
//!
//! 一个演示 SHAKE 可扩展输出函数 (XOF) 的示例。

use hex;
use seal_crypto::{prelude::*, schemes::xof::shake::Shake256};

fn main() -> Result<(), CryptoError> {
    println!("Running SHAKE XOF example... / 正在运行 SHAKE XOF 示例...");

    // --- SHAKE XOF Example ---
    // SHAKE is an Extendable-Output Function (XOF), perfect for deriving multiple
    // keys or keys of arbitrary length from a single input.
    // SHAKE 是一个可扩展输出函数 (XOF)，非常适合从单个输入派生多个密钥或任意长度的密钥。
    println!("\n--- SHAKE256 ---");
    let ikm_shake = b"another-high-entropy-input";
    let salt_shake = b"shake-it-up-salt";
    let info_shake = b"shake-specific-info";

    let shake_scheme = Shake256::default();

    // 1. Using it as a standard KDF with fixed output length.
    // 1. 将其用作具有固定输出长度的标准 KDF。
    println!("  - Using SHAKE as a standard KDF:");
    let derived_key_shake =
        shake_scheme.derive(ikm_shake, Some(salt_shake), Some(info_shake), 32)?;
    println!(
        "    - Derived Key (32 bytes): 0x{}",
        hex::encode(derived_key_shake.as_bytes())
    );

    // 2. Using its XOF capability to stream output via the `XofDerivation` trait.
    // 2. 通过 `XofDerivation` trait 使用其 XOF 功能来流式传输输出。
    println!("  - Using SHAKE as a streamable XOF:");
    let mut reader = shake_scheme.reader(ikm_shake, Some(salt_shake), Some(info_shake))?;

    let mut key1 = [0u8; 32];
    reader.read(&mut key1);
    println!(
        "    - Derived Key 1 from stream (32 bytes): 0x{}",
        hex::encode(&key1)
    );

    let mut key2 = [0u8; 64];
    reader.read(&mut key2);
    println!(
        "    - Derived Key 2 from stream (64 bytes): 0x{}",
        hex::encode(&key2)
    );

    // Verify the first key from the stream matches the one from derive()
    // 验证从流中得到的第一个密钥与从 derive() 中得到的密钥匹配
    assert_eq!(derived_key_shake.as_bytes(), &key1);
    println!("    - Verified: First 32 bytes from stream match the `derive` output. / 验证：流中的前 32 字节与 `derive` 输出匹配。");

    println!("\nSHAKE XOF example completed successfully! / SHAKE XOF 示例成功完成！");

    Ok(())
} 