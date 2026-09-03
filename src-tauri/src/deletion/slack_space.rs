use anyhow::Result;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

pub struct SlackSpaceSanitizer;

impl SlackSpaceSanitizer {
    /// Zeroes out the residual filesystem slack space between the logical end-of-file (EOF)
    /// and the physical cluster boundary allocation (e.g. 4096 bytes).
    pub fn sanitize_file_slack(path: &Path, cluster_size: u64) -> Result<u64> {
        let metadata = path.metadata()?;
        let file_size = metadata.len();
        let remainder = file_size % cluster_size;

        if remainder == 0 {
            return Ok(0); // File aligns perfectly with cluster boundary
        }

        let slack_size = cluster_size - remainder;
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;

        file.seek(SeekFrom::Start(file_size))?;
        let zeroes = vec![0u8; slack_size as usize];
        file.write_all(&zeroes)?;
        file.sync_data()?;

        // Restore original logical file length so file metadata is not enlarged
        file.set_len(file_size)?;
        file.sync_all()?;

        Ok(slack_size)
    }
}
