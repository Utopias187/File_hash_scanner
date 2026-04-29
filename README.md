# File Hash Scanner

A Rust command-line cybersecurity tool that scans files and folders, computes file hashes, and compares them against a local signature database.

This project demonstrates file I/O, hashing, recursive directory traversal, command-line parsing, structured output, and basic malware-signature style detection using Rust.

## Features

- Scan a single file
- Scan folders recursively
- Generate file hashes without scanning
- Support SHA-256, SHA-1, and MD5
- Match file hashes against a local signature database
- Algorithm-aware signature format
- Quiet mode for cleaner scans
- JSON output for machine-readable results
- Skips noisy folders like `target` and `.git`
- Prints a final scan summary

## Requirements

- Rust
- Cargo

Check that Rust is installed:

```bash
rustc --version
cargo --version