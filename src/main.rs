use anyhow::Result;
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;

#[derive(Parser)]
#[command(name = "file-hash-scanner")]
#[command(about = "A simple file hash scanner written in Rust")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        path: String,
    },
}

fn hash_file(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();

    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer)?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    let hash = hasher.finalize();
    Ok(format!("{:x}", hash))
}

fn load_signatures(path: &Path) -> Result<HashMap<String, String>> {
    let content = fs::read_to_string(path)?;
    let mut signatures = HashMap::new();

    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut parts = line.split_whitespace();

        if let Some(hash) = parts.next() {
            let name = parts.collect::<Vec<_>>().join(" ");
            signatures.insert(hash.to_lowercase(), name);
        }
    }

    Ok(signatures)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let signatures = load_signatures(Path::new("signatures.txt"))?;

    match cli.command {
        Commands::Scan { path } => {
            let path = Path::new(&path);
            let hash = hash_file(path)?;

            println!("File: {}", path.display());
            println!("SHA256: {}", hash);

            if let Some(signature_name) = signatures.get(&hash) {
                println!("Status: MATCH FOUND");
                println!("Signature: {}", signature_name);
            } else {
                println!("Status: No match found");
            }
        }
    }

    Ok(())
}