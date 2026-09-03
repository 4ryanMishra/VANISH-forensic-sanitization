use anyhow::{anyhow, Result};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

pub struct FileShredder;

impl FileShredder {
    /// Overwrites a target file in-place with multi-pass patterns, syncs buffers to physical media,
    /// truncates the file length to 0, and unlinks it from the filesystem.
    pub fn shred_file(path: &Path, passes: u32) -> Result<u64> {
        if !path.exists() {
            return Err(anyhow!("Target file does not exist: {:?}", path));
        }

        let metadata = path.metadata()?;
        if !metadata.is_file() {
            return Err(anyhow!("Target path is not a regular file: {:?}", path));
        }

        let file_size = metadata.len();
        if file_size == 0 {
            std::fs::remove_file(path)?;
            return Ok(0);
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;

        let chunk_size = 64 * 1024; // 64KB buffer
        let mut buffer = vec![0u8; chunk_size];
        let mut rng = StdRng::from_entropy();

        for p in 1..=passes.max(1) {
            file.seek(SeekFrom::Start(0))?;
            let mut written: u64 = 0;

            while written < file_size {
                let to_write = (chunk_size as u64).min(file_size - written) as usize;
                match p {
                    1 => buffer[..to_write].fill(0x00),
                    2 => buffer[..to_write].fill(0xFF),
                    _ => rng.fill_bytes(&mut buffer[..to_write]),
                }

                file.write_all(&buffer[..to_write])?;
                written += to_write as u64;
            }

            file.sync_data()?;
        }

        // Truncate to 0 bytes before deleting
        file.set_len(0)?;
        file.sync_all()?;
        drop(file);

        std::fs::remove_file(path)?;
        Ok(file_size)
    }
}
