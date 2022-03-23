use std::path::PathBuf;
use tokio::fs;

pub struct Cache {
    file: PathBuf,
}

impl Cache {
    pub fn new(file: impl Into<PathBuf>) -> Self {
        Self { file: file.into() }
    }

    pub async fn put(&self, data: Vec<u8>) -> Result<(), std::io::Error> {
        fs::write(&self.file, data).await
    }

    pub async fn get(&self) -> Result<Vec<u8>, std::io::Error> {
        fs::read(&self.file).await
    }
}