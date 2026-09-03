use anyhow::Result;
use rand::{rngs::StdRng, RngCore, SeedableRng};

pub enum OverwritePatternType {
    Fixed(u8),
    Inverted(u8),
    PseudoRandom { seed: Option<u64> },
}

pub struct OverwriteEngine;

impl OverwriteEngine {
    /// Executes a sequential multi-pass overwrite stream with progress reporting.
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
}
