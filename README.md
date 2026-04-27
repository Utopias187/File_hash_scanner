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

Use quiet mode:

```bash
cargo run -- scan . --quiet

cargo run -- scan . --json```markdown
- Quiet mode for cleaner scans
- JSON output for machine-readable results

Generate a SHA-256 hash without scanning:

```bash
cargo run -- hash test.txt


Also add this to the features list:

```markdown
- Generate SHA-256 hashes without signature matching