use kaiju_encryption::open_with_hex_key;
use std::fs;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <encrypted_file> <secret_key_hex> <output_file>", args[0]);
        std::process::exit(1);
    }

    let encrypted_file = &args[1];
    let secret_key = &args[2];
    let output_file = &args[3];

    let ciphertext = fs::read(encrypted_file).expect("Failed to read encrypted file");
    println!("Encrypted file size: {} bytes", ciphertext.len());

    match open_with_hex_key(&ciphertext, secret_key) {
        Ok(plaintext) => {
            println!("Decrypted size: {} bytes", plaintext.len());
            fs::write(output_file, &plaintext).expect("Failed to write output");
            println!("Written to {}", output_file);
        }
        Err(e) => {
            eprintln!("Decryption failed: {:?}", e);
            std::process::exit(1);
        }
    }
}
