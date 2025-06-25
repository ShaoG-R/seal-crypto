//! An example demonstrating digital signatures using RSA-4096 with PSS padding and SHA-256.
//!
//! 一个演示数字签名的示例，使用带 PSS 填充和 SHA-256 的 RSA-4096。

use seal_crypto::prelude::*;
use seal_crypto::schemes::asymmetric::traditional::rsa::{Rsa4096, RsaScheme};

fn main() -> Result<(), CryptoError> {
    // Define the concrete RSA scheme we want to use.
    // RsaScheme defaults to using Sha256 as the hasher.
    // 定义我们想要使用的具体 RSA 方案。
    // RsaScheme 默认使用 Sha256 作为哈希函数。
    type MyRsa = RsaScheme<Rsa4096>;

    println!("Running digital signature example... / 正在运行数字签名示例...");

    // 1. Key Generation
    //    A user generates an RSA key pair.
    // 1. 密钥生成
    //    一个用户生成一个 RSA 密钥对。
    println!("\nStep 1: User generates an RSA-4096 key pair with SHA-256. / 步骤1：用户生成 RSA-4096 SHA-256 密钥对。");
    let (public_key, private_key) = MyRsa::generate_keypair()?;
    println!("  - Public Key generated. / 已生成公钥。");
    println!("  - Private Key generated. / 已生成私钥。");

    // 2. Signing
    //    The user signs a message with their private key.
    // 2. 签名
    //    用户使用其私钥对一条消息进行签名。
    println!("\nStep 2: User signs a message. / 步骤2：用户对消息进行签名。");
    let message = b"This message is authentic and untampered.";
    println!(
        "  - Message to be signed: \"{}\" / 待签名消息：\"{}\"",
        String::from_utf8_lossy(message),
        String::from_utf8_lossy(message)
    );

    let signature = MyRsa::sign(&private_key, message)?;
    println!(
        "  - Signature created ({} bytes). / 已创建签名（{}字节）。",
        signature.len(),
        signature.len()
    );

    // 3. Verification
    //    Another user (or the same one) verifies the signature with the public key.
    // 3. 验证
    //    另一个用户（或同一个人）使用公钥来验证签名。
    println!("\nStep 3: Verifying the signature. / 步骤3：验证签名。");

    // The verification should succeed with the correct message and public key.
    // 使用正确的消息和公钥，验证应该成功。
    MyRsa::verify(&public_key, message, &signature)?;
    println!(
        "  - Success! Signature is valid for the original message. / 成功！签名对原始消息有效。"
    );

    // 4. Verification Failure Scenarios
    //    Demonstrate cases where verification should fail.
    // 4. 验证失败场景
    //    演示验证应该失败的几种情况。
    println!("\nStep 4: Demonstrating verification failures. / 步骤4：演示验证失败场景。");

    // Case a: The message is tampered with.
    // 情况a：消息被篡改。
    let tampered_message = b"This message has been tampered with!";
    println!("  - Verifying with a tampered message... / 使用被篡改的消息进行验证...");
    let tampered_result = MyRsa::verify(&public_key, tampered_message, &signature);
    assert!(tampered_result.is_err());
    println!("    -> Correctly failed as expected. / -> 已按预期正确失败。");

    // Case b: A different key is used for verification.
    // 情况b：使用不同的密钥进行验证。
    println!("  - Verifying with a different public key... / 使用不同的公钥进行验证...");
    let (other_public_key, _) = MyRsa::generate_keypair()?;
    let wrong_key_result = MyRsa::verify(&other_public_key, message, &signature);
    assert!(wrong_key_result.is_err());
    println!("    -> Correctly failed as expected. / -> 已按预期正确失败。");

    println!("\nDigital signature flow completed successfully! / 数字签名流程成功完成！");

    Ok(())
}
