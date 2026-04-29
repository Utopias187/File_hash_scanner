use crate::models::HashAlgorithm;
use anyhow::{bail, Result};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

pub fn hash_file(path: &Path, algorithm: HashAlgorithm) -> Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_file_path(file_name: &str) -> std::path::PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        env::temp_dir().join(format!("{}_{}", timestamp, file_name))
    }

    #[test]
    fn test_hash_file_sha256() {
        let path = temp_file_path("hash_test.txt");

        fs::write(&path, "test").unwrap();

        let hash = hash_file(&path, HashAlgorithm::Sha256).unwrap();

        assert_eq!(
            hash,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_hash_file_sha1() {
        let path = temp_file_path("sha1_test.txt");

        fs::write(&path, "test").unwrap();

        let hash = hash_file(&path, HashAlgorithm::Sha1).unwrap();

        assert_eq!(hash, "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_hash_file_md5() {
        let path = temp_file_path("md5_test.txt");

        fs::write(&path, "test").unwrap();

        let hash = hash_file(&path, HashAlgorithm::Md5).unwrap();

        assert_eq!(hash, "098f6bcd4621d373cade4e832627b4f6");

        fs::remove_file(path).unwrap();
    }
}
