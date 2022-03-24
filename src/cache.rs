use std::{path::PathBuf};
use tokio::fs;
use windows::{core::*, Security::Cryptography::DataProtection::*, Security::Cryptography::*, Storage::Streams::*, Win32::System::WinRT::*};

pub struct EncryptedCache {
    file: PathBuf,
}

impl EncryptedCache {
    pub fn new(file: impl Into<PathBuf>) -> Self {
        Self { file: file.into() }
    }

    pub async fn put(&self, data: &str) -> anyhow::Result<()> {
        let provider = DataProtectionProvider::CreateOverloadExplicit("LOCAL=user")?;
        let unprotected = CryptographicBuffer::ConvertStringToBinary(data, BinaryStringEncoding::Utf8)?;
        let protected = provider.ProtectAsync(unprotected)?.get()?;
        let protected_bytes = unsafe { as_mut_bytes(&protected)? };
        fs::write(&self.file, protected_bytes).await?;
        Ok(())
    }
    
    pub async fn get(&self) -> anyhow::Result<String> {
        let protected_bytes = std::fs::read(&self.file)?;
        let provider = DataProtectionProvider::CreateOverloadExplicit("LOCAL=user")?;
        let protected = CryptographicBuffer::CreateFromByteArray(&protected_bytes)?;
        let unprotected = provider.UnprotectAsync(protected)?.get()?;
        Ok(CryptographicBuffer::ConvertBinaryToString(BinaryStringEncoding::Utf8, unprotected)?.to_string())
    }
}

unsafe fn as_mut_bytes(buffer: &IBuffer) -> Result<&mut [u8]> {
    let interop = buffer.cast::<IBufferByteAccess>()?;
    let data = interop.Buffer()?;
    Ok(std::slice::from_raw_parts_mut(data, buffer.Length()? as _))
}