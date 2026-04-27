use anyhow::Result;
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;
use walkdir::WalkDir;

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

fn scan_file(path: &Path, signatures: &HashMap<String, String>) -> Result<()> {
    let hash = hash_file(path)?;

    if let Some(signature_name) = signatures.get(&hash) {
        println!("[MATCH] {} -> {}", path.display(), signature_name);
    } else {
        println!("[OK] {}", path.display());
    }

    Ok(())
}

fn scan_path(path: &Path, signatures: &HashMap<String, String>) -> Result<()> {
    if path.is_file() {
        scan_file(path, signatures)?;
    } else if path.is_dir() {
        for entry in WalkDir::new(path) {
            let entry = entry?;

            if entry.path().is_file() {
                if let Err(error) = scan_file(entry.path(), signatures) {
                    eprintln!("[ERROR] {} -> {}", entry.path().display(), error);
                }
            }
        }
    } else {
        eprintln!("Path does not exist: {}", path.display());
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let signatures = load_signatures(Path::new("signatures.txt"))?;

    match cli.command {
        Commands::Scan { path } => {
            let path = Path::new(&path);
            scan_path(path, &signatures)?;
        }
    }

    Ok(())
}