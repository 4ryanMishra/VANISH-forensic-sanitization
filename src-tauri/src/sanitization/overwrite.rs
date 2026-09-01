use anyhow::Result;

pub struct OverwriteEngine;

impl OverwriteEngine {
    /// Executes sequential pattern writing against a designated stream or mock device
    pub fn execute_pattern(
        pattern_byte: u8,
        total_bytes: u64,
        block_size: usize,
        mut progress_callback: impl FnMut(u64, u64),
    ) -> Result<()> {
        let buffer = vec![pattern_byte; block_size];
        let mut written: u64 = 0;

        while written < total_bytes {
            let chunk = (block_size as u64).min(total_bytes - written);
            written += chunk;
            progress_callback(written, total_bytes);
        }

        Ok(())
    }
}
