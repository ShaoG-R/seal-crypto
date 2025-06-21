//! An example demonstrating hybrid encryption using Kyber for KEM
//! and AES-256-GCM for symmetric encryption.
//!
//! 一个演示混合加密的示例，其中 KEM 使用 Kyber，对称加密使用 AES-256-GCM。

use seal_crypto::prelude::*;
use seal_crypto::systems::{
    asymmetric::kyber::{Kyber1024, KyberScheme},
    symmetric::aes_gcm::{Aes256, AesGcmScheme},
};
use seal_crypto::traits::symmetric::SymmetricCipher;

fn main() -> Result<(), CryptoError> {
    println!("Running hybrid encryption example... / 正在运行混合加密示例...");

    // 1. Key Generation (Recipient)
    //    The recipient generates a Kyber key pair.
    // 1. 密钥生成（接收方）
    //    接收方生成一个 Kyber 密钥对。
    println!("\nStep 1: Recipient generates a Kyber-1024 key pair. / 步骤1：接收方生成 Kyber-1024 密钥对。");
    let (public_key, private_key) = KyberScheme::<Kyber1024>::generate_keypair()?;
    println!(
        "  - Public Key generated ({} bytes) / 已生成公钥（{}字节）",
        public_key.len(),
        public_key.len()
    );
    println!(
        "  - Private Key generated ({} bytes) / 已生成私钥（{}字节）",
        private_key.len(),
        private_key.len()
    );

    // 2. Encryption (Sender)
    //    The sender uses the recipient's public key to perform hybrid encryption.
    // 2. 加密（发送方）
    //    发送方使用接收方的公钥来执行混合加密。
    println!("\nStep 2: Sender encrypts a secret message using the recipient's public key. / 步骤2：发送方使用接收方的公钥加密一条秘密消息。");
    let secret_message = b"This is a super secret message!";
    let associated_data = b"Hybrid Encryption Example";
    println!(
        "  - Plaintext: \"{}\" / 明文：\"{}\"",
        String::from_utf8_lossy(secret_message),
        String::from_utf8_lossy(secret_message)
    );
    println!(
        "  - Associated Data: \"{}\" / 关联数据：\"{}\"",
        String::from_utf8_lossy(associated_data),
        String::from_utf8_lossy(associated_data)
    );

    // The sender encapsulates a shared secret and gets the encapsulated key.
    // 发送方封装一个共享密钥，并得到封装后的密钥。
    let (shared_secret, encapsulated_key) = KyberScheme::<Kyber1024>::encapsulate(&public_key)?;
    println!("  - Shared secret generated and encapsulated. / 已生成并封装共享密钥。");

    // The sender uses the shared secret to encrypt the message with AES-256-GCM.
    // A nonce must be unique for each encryption with the same key.
    // 发送方使用共享密钥通过 AES-256-GCM 加密消息。
    // 对于使用相同密钥的每次加密，nonce 都必须是唯一的。
    let nonce = vec![0u8; <AesGcmScheme<Aes256> as SymmetricCipher>::NONCE_SIZE];
    // In a real application, you would use a secure random number generator
    // to create a unique nonce for each encryption.
    // e.g., use rand::{RngCore, OsRng}; OsRng.fill_bytes(&mut nonce);
    // 在实际应用中，您应该使用一个安全的随机数生成器为每次加密创建唯一的 nonce。
    // 例如：use rand::{RngCore, OsRng}; OsRng.fill_bytes(&mut nonce);

    let ciphertext = AesGcmScheme::<Aes256>::encrypt(
        &shared_secret,
        &nonce,
        secret_message,
        Some(associated_data),
    )?;
    println!(
        "  - Message successfully encrypted with AES-256-GCM. / 消息已通过 AES-256-GCM 成功加密。"
    );
    println!(
        "  - Ciphertext length: {} bytes / 密文长度：{}字节",
        ciphertext.len(),
        ciphertext.len()
    );
    println!(
        "  - Encapsulated key length: {} bytes / 封装密钥长度：{}字节",
        encapsulated_key.len(),
        encapsulated_key.len()
    );

    // The sender transmits the `ciphertext`, `encapsulated_key`, and `nonce` to the recipient.
    // 发送方将 `ciphertext`、`encapsulated_key` 和 `nonce` 传输给接收方。

    // 3. Decryption (Recipient)
    //    The recipient uses their private key and the encapsulated key to decrypt the message.
    // 3. 解密（接收方）
    //    接收方使用他们的私钥和封装密钥来解密消息。
    println!("\nStep 3: Recipient decrypts the message. / 步骤3：接收方解密消息。");

    // The recipient decapsulates the shared secret using their private key.
    // 接收方使用其私钥来解封装共享密钥。
    let decrypted_shared_secret =
        KyberScheme::<Kyber1024>::decapsulate(&private_key, &encapsulated_key)?;
    println!("  - Shared secret successfully decapsulated. / 共享密钥解封装成功。");

    // The recipient uses the decapsulated secret to decrypt the ciphertext.
    // 接收方使用解封装后的密钥来解密密文。
    let decrypted_plaintext = AesGcmScheme::<Aes256>::decrypt(
        &decrypted_shared_secret,
        &nonce,
        &ciphertext,
        Some(associated_data),
    )?;
    println!("  - Ciphertext successfully decrypted with AES-256-GCM. / 密文已通过 AES-256-GCM 成功解密。");

    // 4. Verification
    //    Verify that the decrypted message matches the original.
    // 4. 验证
    //    验证解密后的消息与原始消息是否匹配。
    println!("\nStep 4: Verifying the result. / 步骤4：验证结果。");
    assert_eq!(secret_message.to_vec(), decrypted_plaintext);
    println!("  - Success! Decrypted message matches the original secret message. / 成功！解密后的消息与原始秘密消息匹配。");

    println!("\nHybrid encryption flow completed successfully! / 混合加密流程成功完成！");

    Ok(())
}
