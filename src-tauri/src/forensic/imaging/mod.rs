use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ImagingError {
    #[error("I/O error accessing forensic image: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid sector range: start offset {start} exceeds image size {total}")]
    InvalidSectorRange { start: u64, total: u64 },
    #[error("Image path does not exist or is not a regular file: {0}")]
    FileNotFound(String),
}

/// A strictly read-only, write-blocked forensic image reader.
/// Supports sector-level streaming, chunk reading, and whole-image evidential hashing.
pub struct RawImageReader {
    path: PathBuf,
    file_size: u64,
    sector_size: u32,
    acquisition_sha256: Option<String>,
}

impl RawImageReader {
    pub const DEFAULT_SECTOR_SIZE: u32 = 512;
    pub const ADVANCED_FORMAT_SECTOR_SIZE: u32 = 4096;

    /// Opens a forensic disk image file in strictly read-only mode.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, ImagingError> {
        let path_buf = path.as_ref().to_path_buf();
        if !path_buf.exists() || !path_buf.is_file() {
            return Err(ImagingError::FileNotFound(path_buf.display().to_string()));
        }

        // Open read-only
        let file = File::open(&path_buf)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len();

        Ok(Self {
            path: path_buf,
            file_size,
            sector_size: Self::DEFAULT_SECTOR_SIZE,
            acquisition_sha256: None,
        })
    }

    /// Sets the sector size (e.g. 512 or 4096 bytes).
    pub fn with_sector_size(mut self, sector_size: u32) -> Self {
        self.sector_size = sector_size;
        self
    }

    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    pub fn total_sectors(&self) -> u64 {
        if self.sector_size == 0 {
            0
        } else {
            self.file_size / self.sector_size as u64
        }
    }

    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Computes and caches the SHA-256 hash of the entire forensic image.
    /// This establishes evidential chain of custody.
    pub fn compute_sha256(&mut self) -> Result<String, ImagingError> {
        let file = File::open(&self.path)?;
        let mut reader = BufReader::with_capacity(1024 * 1024, file);
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let hash_hex = hex::encode(hasher.finalize());
        self.acquisition_sha256 = Some(hash_hex.clone());
        Ok(hash_hex)
    }

    pub fn acquisition_sha256(&self) -> Option<&str> {
        self.acquisition_sha256.as_deref()
    }

    /// Reads an exact range of bytes from the image at the given byte offset.
    pub fn read_range(&self, offset: u64, length: usize) -> Result<Vec<u8>, ImagingError> {
        if offset > self.file_size {
            return Err(ImagingError::InvalidSectorRange {
                start: offset,
                total: self.file_size,
            });
        }

        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(offset))?;

        let bytes_to_read = std::cmp::min(length as u64, self.file_size - offset) as usize;
        let mut buf = vec![0u8; bytes_to_read];
        file.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Reads one or more sectors starting at `sector_index`.
    pub fn read_sectors(&self, sector_index: u64, count: usize) -> Result<Vec<u8>, ImagingError> {
        let byte_offset = sector_index * self.sector_size as u64;
        let byte_length = count * self.sector_size as usize;
        self.read_range(byte_offset, byte_length)
    }

    /// Reads the entire image into memory (for virtual images / lab test targets).
    pub fn read_all(&self) -> Result<Vec<u8>, ImagingError> {
        let mut file = File::open(&self.path)?;
        let mut buffer = Vec::with_capacity(self.file_size as usize);
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    /// Iterates over blocks of the image with a specified chunk size and overlap.
    /// Overlap ensures signatures spanning block boundaries are not missed.
    pub fn stream_chunks<F>(&self, chunk_size: usize, overlap: usize, mut callback: F) -> Result<(), ImagingError>
    where
        F: FnMut(u64, &[u8]) -> Result<bool, ImagingError>, // (byte_offset, chunk) -> continue_scan
    {
        let file = File::open(&self.path)?;
        let mut reader = BufReader::with_capacity(1024 * 1024, file);
        let mut offset = 0u64;

        let mut carry = Vec::new();
        let mut read_buf = vec![0u8; chunk_size];

        while offset < self.file_size {
            let to_read = std::cmp::min(chunk_size as u64, self.file_size - offset) as usize;
            let mut current_chunk = Vec::with_capacity(carry.len() + to_read);
            current_chunk.extend_from_slice(&carry);

            let bytes_read = reader.read(&mut read_buf[..to_read])?;
            if bytes_read == 0 {
                break;
            }
            current_chunk.extend_from_slice(&read_buf[..bytes_read]);

            let chunk_start_offset = if offset >= carry.len() as u64 {
                offset - carry.len() as u64
            } else {
                0
            };

            let should_continue = callback(chunk_start_offset, &current_chunk)?;
            if !should_continue {
                break;
            }

            offset += bytes_read as u64;

            // Retain overlap tail for next iteration
            if overlap > 0 && current_chunk.len() > overlap {
                carry = current_chunk[current_chunk.len() - overlap..].to_vec();
            } else {
                carry.clear();
            }
        }

        Ok(())
    }
}
