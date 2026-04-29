use crate::hashing::hash_file;
use crate::models::{HashAlgorithm, MatchResult, ScanStats};
use crate::signatures::signature_key;
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use walkdir::{DirEntry, WalkDir};

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

pub fn scan_path(
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

pub fn print_text_summary(stats: &ScanStats) {
    println!();
    println!("Scan complete.");
    println!("Algorithm: {}", stats.algorithm);
    println!("Files scanned: {}", stats.files_scanned);
    println!("Matches found: {}", stats.matches_found);
    println!("Errors: {}", stats.errors);
}
