use anyhow::Result;
use clap::{Parser, Subcommand};
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
    },
}

struct ScanStats {
    files_scanned: usize,
    matches_found: usize,
    errors: usize,
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

fn should_skip(entry: &DirEntry) -> bool {
    let file_name = entry.file_name().to_string_lossy();

    file_name == "target" || file_name == ".git"
}

fn scan_file(
    path: &Path,
    signatures: &HashMap<String, String>,
    stats: &mut ScanStats,
    quiet: bool,
) -> Result<()> {
    let hash = hash_file(path)?;
    stats.files_scanned += 1;

    if let Some(signature_name) = signatures.get(&hash) {
        stats.matches_found += 1;
        println!("[MATCH] {} -> {}", path.display(), signature_name);
    } else if !quiet {
        println!("[OK] {}", path.display());
    }

    Ok(())
}

fn scan_path(
    path: &Path,
    signatures: &HashMap<String, String>,
    stats: &mut ScanStats,
    quiet: bool,
) -> Result<()> {
    if path.is_file() {
        if let Err(error) = scan_file(path, signatures, stats, quiet) {
            stats.errors += 1;
            eprintln!("[ERROR] {} -> {}", path.display(), error);
        }
    } else if path.is_dir() {
        for entry in WalkDir::new(path)
            .into_iter()
            .filter_entry(|e| !should_skip(e))
        {
            match entry {
                Ok(entry) => {
                    if entry.path().is_file() {
                        if let Err(error) = scan_file(entry.path(), signatures, stats, quiet) {
                            stats.errors += 1;
                            eprintln!("[ERROR] {} -> {}", entry.path().display(), error);
                        }
                    }
                }
                Err(error) => {
                    stats.errors += 1;
                    eprintln!("[ERROR] {}", error);
                }
            }
        }
    } else {
        stats.errors += 1;
        eprintln!("Path does not exist: {}", path.display());
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut stats = ScanStats {
        files_scanned: 0,
        matches_found: 0,
        errors: 0,
    };

    match cli.command {
        Commands::Scan {
            path,
            signatures,
            quiet,
        } => {
            let signatures = load_signatures(Path::new(&signatures))?;
            let path = Path::new(&path);

            scan_path(path, &signatures, &mut stats, quiet)?;
        }
    }

    println!();
    println!("Scan complete.");
    println!("Files scanned: {}", stats.files_scanned);
    println!("Matches found: {}", stats.matches_found);
    println!("Errors: {}", stats.errors);

    Ok(())
}
