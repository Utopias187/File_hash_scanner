use anyhow::{bail, Result};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub fn signature_key(algorithm: &str, hash: &str) -> String {
    format!("{}:{}", algorithm.to_lowercase(), hash.to_lowercase())
}

pub fn load_signatures(path: &Path) -> Result<HashMap<String, String>> {
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
    fn test_signature_key_lowercases_algorithm_and_hash() {
        let key = signature_key("SHA256", "ABC123");

        assert_eq!(key, "sha256:abc123");
    }

    #[test]
    fn test_load_signatures() {
        let path = temp_file_path("signatures_test.txt");

        let content = "\
# test signature file
sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 test-sha256
sha1 a94a8fe5ccb19ba61c4c0873d391e987982fbbd3 test-sha1
md5 098f6bcd4621d373cade4e832627b4f6 test-md5
";

        fs::write(&path, content).unwrap();

        let signatures = load_signatures(&path).unwrap();

        assert_eq!(
            signatures
                .get("sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
            Some(&"test-sha256".to_string())
        );

        assert_eq!(
            signatures.get("sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"),
            Some(&"test-sha1".to_string())
        );

        assert_eq!(
            signatures.get("md5:098f6bcd4621d373cade4e832627b4f6"),
            Some(&"test-md5".to_string())
        );

        fs::remove_file(path).unwrap();
    }
}
