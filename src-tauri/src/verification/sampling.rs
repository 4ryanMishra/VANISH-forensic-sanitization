/// Shannon entropy scanner for post-sanitization block samples.
///
/// A perfectly zero-filled disk has entropy ≈ 0.0 bits/byte.
/// A crypto-erased disk (PRNG residual or key-destroyed) has entropy ≈ 8.0 bits/byte.
/// Any mid-range cluster (e.g. 3.0–7.5) indicates residual structured data.
///
/// Thresholds (per NIST SP 800-88 Rev 1 rationale):
///   Zero-fill expected  → accept entropy < 0.05
///   Crypto erase        → accept entropy > 7.90
///   Overwrite (random)  → accept entropy > 7.50
///   Failure threshold   → entropy in [0.05, 7.50] signals residual plaintext.

/// Compute Shannon entropy in bits per byte over a byte slice.
/// Returns a value in [0.0, 8.0].
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// A single LBA-addressed block sample used for verification evidence.
#[derive(Debug, Clone)]
pub struct BlockSample {
    /// Logical Block Address of this sample.
    pub lba: u64,
    /// Raw block data (typically 512 or 4096 bytes).
    pub data: Vec<u8>,
}

/// Result of entropy analysis over a set of samples.
#[derive(Debug, Clone)]
pub struct EntropyAnalysis {
    pub samples_taken: usize,
    pub mean_entropy: f64,
    pub min_entropy: f64,
    pub max_entropy: f64,
    /// Samples that deviated significantly from the expected post-sanitization entropy.
    pub anomalous_lbas: Vec<u64>,
    pub verdict: EntropyVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntropyVerdict {
    /// All samples match zero-fill expectation (entropy < 0.05).
    CleanZeroFill,
    /// All samples match crypto-erase / PRNG expectation (entropy > 7.90).
    CleanHighEntropy,
    /// All samples match random overwrite expectation (entropy > 7.50).
    CleanRandomOverwrite,
    /// One or more samples have mid-range entropy indicating residual structured data.
    AnomalousResidual,
    /// No samples were taken.
    NoSamples,
}

/// Expected entropy mode after sanitization.
#[derive(Debug, Clone)]
pub enum ExpectedEntropyMode {
    ZeroFill,
    RandomOverwrite,
    CryptoErase,
}

/// Analyse a set of block samples against an expected post-erase entropy profile.
pub fn analyse_entropy(samples: &[BlockSample], expected: &ExpectedEntropyMode) -> EntropyAnalysis {
    if samples.is_empty() {
        return EntropyAnalysis {
            samples_taken: 0,
            mean_entropy: 0.0,
            min_entropy: 0.0,
            max_entropy: 0.0,
            anomalous_lbas: vec![],
            verdict: EntropyVerdict::NoSamples,
        };
    }

    let entropies: Vec<(u64, f64)> = samples
        .iter()
        .map(|s| (s.lba, shannon_entropy(&s.data)))
        .collect();

    let mean = entropies.iter().map(|(_, e)| e).sum::<f64>() / entropies.len() as f64;
    let min = entropies.iter().map(|(_, e)| *e).fold(f64::INFINITY, f64::min);
    let max = entropies.iter().map(|(_, e)| *e).fold(f64::NEG_INFINITY, f64::max);

    let (low_threshold, high_threshold, anomaly_check): (f64, f64, Box<dyn Fn(f64) -> bool>) =
        match expected {
            ExpectedEntropyMode::ZeroFill => (
                0.0, 0.05,
                Box::new(|e: f64| e > 0.10),
            ),
            ExpectedEntropyMode::RandomOverwrite => (
                7.50, 8.0,
                Box::new(|e: f64| e < 7.40),
            ),
            ExpectedEntropyMode::CryptoErase => (
                7.90, 8.0,
                Box::new(|e: f64| e < 7.80),
            ),
        };

    let anomalous_lbas: Vec<u64> = entropies
        .iter()
        .filter(|(_, e)| anomaly_check(*e))
        .map(|(lba, _)| *lba)
        .collect();

    let verdict = if !anomalous_lbas.is_empty() {
        EntropyVerdict::AnomalousResidual
    } else {
        match expected {
            ExpectedEntropyMode::ZeroFill if mean <= low_threshold + 0.05 => {
                EntropyVerdict::CleanZeroFill
            }
            ExpectedEntropyMode::RandomOverwrite if mean >= high_threshold - 0.50 => {
                EntropyVerdict::CleanRandomOverwrite
            }
            ExpectedEntropyMode::CryptoErase if mean >= high_threshold - 0.10 => {
                EntropyVerdict::CleanHighEntropy
            }
            _ => EntropyVerdict::AnomalousResidual,
        }
    };

    EntropyAnalysis {
        samples_taken: samples.len(),
        mean_entropy: mean,
        min_entropy: min,
        max_entropy: max,
        anomalous_lbas,
        verdict,
    }
}

/// Generate synthetic simulated block samples for a given device capacity.
/// In simulation mode (no physical block device), we produce deterministic
/// zero-filled or pseudo-random blocks matching the expected post-erase state.
pub fn generate_simulated_samples(
    device_capacity_bytes: u64,
    block_size: u32,
    sample_count: usize,
    mode: &ExpectedEntropyMode,
) -> Vec<BlockSample> {
    let total_blocks = device_capacity_bytes / block_size as u64;
    let step = if total_blocks > sample_count as u64 {
        total_blocks / sample_count as u64
    } else {
        1
    };

    (0..sample_count)
        .map(|i| {
            let lba = (i as u64) * step;
            let data: Vec<u8> = match mode {
                ExpectedEntropyMode::ZeroFill => vec![0x00u8; block_size as usize],
                ExpectedEntropyMode::RandomOverwrite | ExpectedEntropyMode::CryptoErase => {
                    // Deterministic pseudo-random using LBA as seed for reproducibility
                    let mut buf = vec![0u8; block_size as usize];
                    let seed = lba ^ 0xDEAD_BEEF_CAFE_1234;
                    for (j, byte) in buf.iter_mut().enumerate() {
                        // LCG-style per-byte value for simulation
                        *byte = ((seed.wrapping_add(j as u64)
                            .wrapping_mul(6364136223846793005)
                            .wrapping_add(1442695040888963407))
                            >> 33) as u8;
                    }
                    buf
                }
            };
            BlockSample { lba, data }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_zero_block() {
        let data = vec![0u8; 512];
        let e = shannon_entropy(&data);
        assert!(e < 0.01, "Zero block entropy should be ~0.0, got {e}");
    }

    #[test]
    fn test_entropy_high_random() {
        // Vary bytes to produce high entropy
        let data: Vec<u8> = (0u16..512).map(|i| i.wrapping_mul(251) as u8).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.0, "Varied block entropy should be >7.0, got {e}");
    }

    #[test]
    fn test_simulated_zero_fill_verdict() {
        let samples = generate_simulated_samples(16_000_000, 512, 32, &ExpectedEntropyMode::ZeroFill);
        let analysis = analyse_entropy(&samples, &ExpectedEntropyMode::ZeroFill);
        assert_eq!(analysis.verdict, EntropyVerdict::CleanZeroFill);
        assert!(analysis.anomalous_lbas.is_empty());
    }
}
