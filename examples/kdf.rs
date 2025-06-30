//! An example demonstrating Key Derivation Functions (KDFs), specifically
//! HKDF and the configurable PBKDF2.
//!
//! 一个演示密钥派生函数 (KDF) 的示例，特别是 HKDF 和可配置的 PBKDF2。

use seal_crypto::{
    prelude::*,
    schemes::kdf::{
        hkdf::{HkdfSha256, HkdfSha512},
        pbkdf2::{Pbkdf2Sha256, Pbkdf2Sha512, PBKDF2_DEFAULT_ITERATIONS},
    },
};
use hex;

fn main() -> Result<(), CryptoError> {
    println!("Running KDF example... / 正在运行 KDF 示例...");

    // --- HKDF Example ---
    // HKDF is suitable for deriving keys from high-entropy inputs, like
    // secrets from a key exchange.
    // HKDF 适用于从高熵输入（如密钥交换的秘密）派生密钥。
    println!("\n--- HKDF-SHA256 ---");
    let ikm_hkdf = b"this-is-a-high-entropy-input-key";
    let salt_hkdf = b"some-random-salt";
    let info_hkdf = b"context-specific-info";
    let output_len = 32;

    let hkdf_scheme = HkdfSha256::default();
    let derived_key_hkdf =
        hkdf_scheme.derive(ikm_hkdf, Some(salt_hkdf), Some(info_hkdf), output_len)?;

    println!(
        "  - HKDF Input Key Material (IKM): \"{}\"",
        String::from_utf8_lossy(ikm_hkdf)
    );
    println!(
        "  - Derived Key ({} bytes): 0x{}",
        derived_key_hkdf.as_bytes().len(),
        hex::encode(derived_key_hkdf.as_bytes())
    );

    // Using HKDF-SHA512 is just as easy.
    // 使用 HKDF-SHA512 同样简单。
    let hkdf_sha512_scheme = HkdfSha512::default();
    let _derived_key_hkdf_512 =
        hkdf_sha512_scheme.derive(ikm_hkdf, Some(salt_hkdf), Some(info_hkdf), 64)?;

    // --- PBKDF2 Example ---
    // PBKDF2 is ideal for deriving keys from low-entropy inputs like passwords,
    // thanks to its configurable iteration count which slows down brute-force attacks.
    // PBKDF2 因其可配置的迭代次数，非常适合从密码等低熵输入中派生密钥，
    // 因为它能减慢暴力破解攻击的速度。
    println!("\n--- PBKDF2-SHA256 ---");
    let password = b"a-very-common-password";
    let salt_pbkdf2 = b"another-unique-salt";
    let output_len_pbkdf2 = 32;

    // Use the recommended default number of iterations.
    // 使用推荐的默认迭代次数。
    let pbkdf2_default_scheme = Pbkdf2Sha256::default();
    println!(
        "  - Deriving key with default iterations: {}",
        pbkdf2_default_scheme.iterations
    );
    let derived_key_pbkdf2_default =
        pbkdf2_default_scheme.derive(password, Some(salt_pbkdf2), None, output_len_pbkdf2)?;
    println!(
        "  - PBKDF2 Input Password: \"{}\"",
        String::from_utf8_lossy(password)
    );
    println!(
        "  - Derived Key (Default Iterations): 0x{}",
        hex::encode(derived_key_pbkdf2_default.as_bytes())
    );

    // Use a custom number of iterations for different security requirements.
    // (Note: In tests or non-critical contexts, a low iteration count is used for speed)
    // 根据不同的安全需求使用自定义的迭代次数。
    // （注意：在测试或非关键上下文中，为了速度会使用较低的迭代次数）
    let custom_iterations = 1000;
    let pbkdf2_custom_scheme = Pbkdf2Sha256::new(custom_iterations);
    println!(
        "  - Deriving key with custom iterations: {}",
        pbkdf2_custom_scheme.iterations
    );
    let derived_key_pbkdf2_custom =
        pbkdf2_custom_scheme.derive(password, Some(salt_pbkdf2), None, output_len_pbkdf2)?;
    println!(
        "  - Derived Key (Custom Iterations): 0x{}",
        hex::encode(derived_key_pbkdf2_custom.as_bytes())
    );

    // PBKDF2 requires a salt. The derive function will return an error if no salt is provided.
    // PBKDF2 需要盐。如果未提供盐，derive 函数将返回错误。
    let no_salt_result = pbkdf2_default_scheme.derive(password, None, None, output_len_pbkdf2);
    assert!(no_salt_result.is_err());
    println!("  - Correctly failed when no salt was provided for PBKDF2. / PBKDF2 在未提供盐的情况下正确失败。");

    // Using PBKDF2-SHA512 is also straightforward.
    // 使用 PBKDF2-SHA512 也同样直接。
    let pbkdf2_sha512_scheme = Pbkdf2Sha512::new(PBKDF2_DEFAULT_ITERATIONS);
    let _derived_key_pbkdf2_512 =
        pbkdf2_sha512_scheme.derive(password, Some(salt_pbkdf2), None, 64)?;

    println!("\nKDF example completed successfully! / KDF 示例成功完成！");

    Ok(())
} 