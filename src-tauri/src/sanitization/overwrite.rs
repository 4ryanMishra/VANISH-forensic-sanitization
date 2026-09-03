use anyhow::{Context, Result};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverwritePatternType {
    Fixed(u8),
    Inverted(u8),
    PseudoRandom { seed: Option<u64> },
}

pub struct OverwriteEngine;

impl OverwriteEngine {
    /// Executes a sequential multi-pass overwrite stream in-memory with progress reporting (for simulated targets).
    pub fn execute_stream(
        pattern_type: OverwritePatternType,
        total_bytes: u64,
        block_size: usize,
        mut progress_cb: impl FnMut(u64, u64),
    ) -> Result<()> {
        let mut buffer = vec![0u8; block_size];
        let mut written: u64 = 0;

        match pattern_type {
            OverwritePatternType::Fixed(byte_val) => {
                buffer.fill(byte_val);
                while written < total_bytes {
                    let chunk = (block_size as u64).min(total_bytes - written);
                    written += chunk;
                    progress_cb(written, total_bytes);
                }
            }
            OverwritePatternType::Inverted(base_byte) => {
                let inverted_byte = !base_byte;
                buffer.fill(inverted_byte);
                while written < total_bytes {
                    let chunk = (block_size as u64).min(total_bytes - written);
                    written += chunk;
                    progress_cb(written, total_bytes);
                }
            }
            OverwritePatternType::PseudoRandom { seed } => {
                let mut rng = match seed {
                    Some(s) => StdRng::seed_from_u64(s),
                    None => StdRng::from_entropy(),
                };

                while written < total_bytes {
                    rng.fill_bytes(&mut buffer);
                    let chunk = (block_size as u64).min(total_bytes - written);
                    written += chunk;
                    progress_cb(written, total_bytes);
                }
            }
        }

        Ok(())
    }

    /// Executes genuine raw block writes directly to a target file or block device path with O_SYNC / flush.
    pub fn execute_block_overwrite(
        device_path: &Path,
        pattern_type: OverwritePatternType,
        total_bytes: u64,
        block_size: usize,
        mut progress_cb: impl FnMut(u64, u64),
    ) -> Result<u64> {
        if total_bytes == 0 {
            return Ok(0);
        }

        let chunk_size = if block_size == 0 { 64 * 1024 } else { block_size.min(1024 * 1024) };
        let mut buffer = vec![0u8; chunk_size];

        let mut file = OpenOptions::new()
            .write(true)
            .open(device_path)
            .with_context(|| format!("Failed to open target block path '{:?}' for raw write", device_path))?;

        file.seek(SeekFrom::Start(0))
            .with_context(|| format!("Failed to seek to LBA 0 on '{:?}'", device_path))?;

        let mut written: u64 = 0;
        let mut rng = if let OverwritePatternType::PseudoRandom { seed } = pattern_type {
            Some(match seed {
                Some(s) => StdRng::seed_from_u64(s),
                None => StdRng::from_entropy(),
            })
        } else {
            None
        };

        if let OverwritePatternType::Fixed(val) = pattern_type {
            buffer.fill(val);
        } else if let OverwritePatternType::Inverted(val) = pattern_type {
            buffer.fill(!val);
        }

        while written < total_bytes {
            let bytes_to_write = ((chunk_size as u64).min(total_bytes - written)) as usize;

            if let Some(ref mut r) = rng {
                r.fill_bytes(&mut buffer[..bytes_to_write]);
            }

            file.write_all(&buffer[..bytes_to_write])
                .with_context(|| format!("Write error at offset {} on '{:?}'", written, device_path))?;

            written += bytes_to_write as u64;
            progress_cb(written, total_bytes);
        }

        file.sync_data()
            .or_else(|_| file.sync_all())
            .with_context(|| format!("Failed to flush buffers to storage on '{:?}'", device_path))?;

        Ok(written)
    }
}
