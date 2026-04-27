# File Hash Scanner

A Rust command-line cybersecurity tool that scans files and folders, computes SHA-256 hashes, and compares them against a local signature database.

## Features

- Scan a single file
- Scan folders recursively
- Compute SHA-256 file hashes
- Match hashes against a local signature file
- Print scan summary with total files, matches, and errors
- Support custom signature database paths

## Usage

Scan a file:

```bash
cargo run -- scan test.txt