pub mod container;
pub mod scanner;
pub mod signature;

pub use container::*;
pub use scanner::*;
pub use signature::*;

pub struct CarvingEngine;

impl CarvingEngine {
    pub fn scan_raw(data: &[u8], base_offset: u64) -> Vec<CarvedCandidate> {
        PatternScanner::scan_buffer(data, base_offset)
    }
}
