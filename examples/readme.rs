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