use clap::ValueEnum;
use serde::Serialize;
use std::fmt;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum HashAlgorithm {
    Sha256,
    Sha1,
    Md5,
}

impl HashAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha1 => "sha1",
            HashAlgorithm::Md5 => "md5",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "SHA256",
            HashAlgorithm::Sha1 => "SHA1",
            HashAlgorithm::Md5 => "MD5",
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Serialize)]
pub struct MatchResult {
    pub path: String,
    pub algorithm: String,
    pub hash: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct ScanStats {
    pub algorithm: String,
    pub files_scanned: usize,
    pub matches_found: usize,
    pub errors: usize,
    pub matches: Vec<MatchResult>,
}
