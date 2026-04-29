mod hashing;
mod models;
mod scanner;
mod signatures;

use anyhow::Result;
use clap::{Parser, Subcommand};
use models::{HashAlgorithm, ScanStats};
use scanner::{print_text_summary, scan_path};
use signatures::load_signatures;
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

        #[arg(short, long, default_value = "signatures.txt")]
        signatures: String,

        #[arg(short, long)]
        quiet: bool,

        #[arg(long)]
        json: bool,

        #[arg(short, long, value_enum, default_value_t = HashAlgorithm::Sha256)]
        algorithm: HashAlgorithm,
    },

    Hash {
        path: String,

        #[arg(short, long, value_enum, default_value_t = HashAlgorithm::Sha256)]
        algorithm: HashAlgorithm,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            signatures,
            quiet,
            json,
            algorithm,
        } => {
            let signatures_path = Path::new(&signatures);

            let signatures = load_signatures(signatures_path).map_err(|error| {
                anyhow::anyhow!(
                    "Could not load signature file: {}\nReason: {}\nExpected format:\n<algorithm> <hash> <signature-name>\nExample:\nsha256 99f86e1be6de5ae82b3f23977b65ebe43cb8359b37b6cf0ab8e6c2eaa0c99193 test-file-sha256-match",
                    signatures_path.display(),
                    error
                )
            })?;

            let mut stats = ScanStats {
                algorithm: algorithm.as_str().to_string(),
                files_scanned: 0,
                matches_found: 0,
                errors: 0,
                matches: Vec::new(),
            };

            let path = Path::new(&path);
            scan_path(path, &signatures, &mut stats, quiet, json, algorithm)?;

            if json {
                let output = serde_json::to_string_pretty(&stats)?;
                println!("{}", output);
            } else {
                print_text_summary(&stats);
            }
        }

        Commands::Hash { path, algorithm } => {
            let path = Path::new(&path);
            let hash = hashing::hash_file(path, algorithm)?;

            println!("File: {}", path.display());
            println!("Algorithm: {}", algorithm.display_name());
            println!("{}: {}", algorithm.display_name(), hash);
        }
    }

    Ok(())
}
