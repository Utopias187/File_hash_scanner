use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use md5::Md5;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;
use walkdir::{DirEntry, WalkDir};

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

#[derive(Clone, Copy, ValueEnum)]
enum HashAlgorithm {
    Sha256,
    Sha1,
    Md5,
}

impl HashAlgorithm {
    fn as_str(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha1 => "sha1",
            HashAlgorithm::Md5 => "md5",
        }
    }

    fn display_name(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "SHA256",
            HashAlgorithm::Sha1 => "SHA1",
            HashAlgorithm::Md5 => "MD5",
        }
    }
}

#[derive(Serialize)]
struct MatchResult {
    path: String,
    algorithm: String,
    hash: String,
    signature: String,
}

#[derive(Serialize)]
struct ScanStats {
    algorithm: String,
    files_scanned: usize,
    matches_found: usize,
    errors: usize,
    matches: Vec<MatchResult>,
}

fn hash_file(path: &Path, algorithm: HashAlgorithm) -> Result<String> {
    if !path.is_file() {
        bail!("Path is not a file: {}", path.display());
    }

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buffer = [0u8; 8192];

    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();

            loop {
                let bytes_read = reader.read(&mut buffer)?;

                if bytes_read == 0 {
                    break;
                }

                hasher.update(&buffer[..bytes_read]);
            }

            Ok(format!("{:x}", hasher.finalize()))
        }

        HashAlgorithm::Sha1 => {
            let mut hasher = Sha1::new();

            loop {
                let bytes_read = reader.read(&mut buffer)?;

                if bytes_read == 0 {
                    break;
                }

                hasher.update(&buffer[..bytes_read]);
            }

            Ok(format!("{:x}", hasher.finalize()))
        }

        HashAlgorithm::Md5 => {
            let mut hasher = Md5::new();

            loop {
                let bytes_read = reader.read(&mut buffer)?;

                if bytes_read == 0 {
                    break;
                }

                hasher.update(&buffer[..bytes_read]);
            }

            Ok(format!("{:x}", hasher.finalize()))
        }
    }
}

fn signature_key(algorithm: &str, hash: &str) -> String {
    format!("{}:{}", algorithm.to_lowercase(), hash.to_lowercase())
}

fn load_signatures(path: &Path) -> Result<HashMap<String, String>> {
    let content = fs::read_to_string(path)?;
    let mut signatures = HashMap::new();

    for (line_number, line) in content.lines().enumerate() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 3 {
            bail!(
                "Invalid signature on line {}. Expected: <algorithm> <hash> <signature-name>",
                line_number + 1
            );
        }

        let algorithm = parts[0].to_lowercase();

        if algorithm != "sha256" && algorithm != "sha1" && algorithm != "md5" {
            bail!(
                "Unsupported algorithm '{}' on line {}. Use sha256, sha1, or md5.",
                parts[0],
                line_number + 1
            );
        }

        let hash = parts[1].to_lowercase();
        let name = parts[2..].join(" ");

        signatures.insert(signature_key(&algorithm, &hash), name);
    }

    Ok(signatures)
}

fn should_skip(entry: &DirEntry) -> bool {
    let file_name = entry.file_name().to_string_lossy();

    file_name == "target" || file_name == ".git"
}

fn scan_file(
    path: &Path,
    signatures: &HashMap<String, String>,
    stats: &mut ScanStats,
    quiet: bool,
    json: bool,
    algorithm: HashAlgorithm,
) -> Result<()> {
    let hash = hash_file(path, algorithm)?;
    stats.files_scanned += 1;

    let key = signature_key(algorithm.as_str(), &hash);

    if let Some(signature_name) = signatures.get(&key) {
        stats.matches_found += 1;

        stats.matches.push(MatchResult {
            path: path.display().to_string(),
            algorithm: algorithm.as_str().to_string(),
            hash,
            signature: signature_name.to_string(),
        });

        if !json {
            println!(
                "[MATCH] {} -> {} ({})",
                path.display(),
                signature_name,
                algorithm.display_name()
            );
        }
    } else if !quiet && !json {
        println!("[OK] {}", path.display());
    }

    Ok(())
}

fn scan_path(
    path: &Path,
    signatures: &HashMap<String, String>,
    stats: &mut ScanStats,
    quiet: bool,
    json: bool,
    algorithm: HashAlgorithm,
) -> Result<()> {
    if path.is_file() {
        if let Err(error) = scan_file(path, signatures, stats, quiet, json, algorithm) {
            stats.errors += 1;

            if !json {
                eprintln!("[ERROR] {} -> {}", path.display(), error);
            }
        }
    } else if path.is_dir() {
        for entry in WalkDir::new(path)
            .into_iter()
            .filter_entry(|e| !should_skip(e))
        {
            match entry {
                Ok(entry) => {
                    if entry.path().is_file() {
                        if let Err(error) =
                            scan_file(entry.path(), signatures, stats, quiet, json, algorithm)
                        {
                            stats.errors += 1;

                            if !json {
                                eprintln!("[ERROR] {} -> {}", entry.path().display(), error);
                            }
                        }
                    }
                }
                Err(error) => {
                    stats.errors += 1;

                    if !json {
                        eprintln!("[ERROR] {}", error);
                    }
                }
            }
        }
    } else {
        stats.errors += 1;

        if !json {
            eprintln!("Path does not exist: {}", path.display());
        }
    }

    Ok(())
}

fn print_text_summary(stats: &ScanStats) {
    println!();
    println!("Scan complete.");
    println!("Algorithm: {}", stats.algorithm);
    println!("Files scanned: {}", stats.files_scanned);
    println!("Matches found: {}", stats.matches_found);
    println!("Errors: {}", stats.errors);
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
            let hash = hash_file(path, algorithm)?;

            println!("File: {}", path.display());
            println!("Algorithm: {}", algorithm.display_name());
            println!("{}: {}", algorithm.display_name(), hash);
        }
    }

    Ok(())
}
