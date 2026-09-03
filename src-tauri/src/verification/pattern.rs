/// Post-sanitization pattern checker for L2 host-visible verification.
///
/// Checks whether sampled blocks comply with the expected byte pattern:
///   - Zero-fill:  every byte == 0x00
///   - Ones-fill:  every byte == 0xFF  (used in some DoD/NIST final passes)
///   - Alternating: alternating 0x55 / 0xAA (DoD 3-pass pattern 2)
///
/// Pattern checking is complementary to entropy analysis — it gives
/// a deterministic pass/fail, whereas entropy gives probabilistic confidence.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedPattern {
    Zero,
    Ones,
    Alternating55AA,
    Random, // No deterministic pattern check possible — rely on entropy only
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternCheckResult {
    Passed,
    Failed { first_violation_lba: u64, expected_byte: u8, found_byte: u8 },
    NotApplicable,
}

/// Check if a single block matches the expected byte pattern.
pub fn check_block_pattern(
    lba: u64,
    data: &[u8],
    pattern: &ExpectedPattern,
) -> PatternCheckResult {
    match pattern {
        ExpectedPattern::Zero => {
            for (i, &b) in data.iter().enumerate() {
                if b != 0x00 {
                    return PatternCheckResult::Failed {
                        first_violation_lba: lba,
                        expected_byte: 0x00,
                        found_byte: b,
                    };
                }
                let _ = i;
            }
            PatternCheckResult::Passed
        }
        ExpectedPattern::Ones => {
            for &b in data.iter() {
                if b != 0xFF {
                    return PatternCheckResult::Failed {
                        first_violation_lba: lba,
                        expected_byte: 0xFF,
                        found_byte: b,
                    };
                }
            }
            PatternCheckResult::Passed
        }
        ExpectedPattern::Alternating55AA => {
            for (i, &b) in data.iter().enumerate() {
                let expected = if i % 2 == 0 { 0x55 } else { 0xAA };
                if b != expected {
                    return PatternCheckResult::Failed {
                        first_violation_lba: lba,
                        expected_byte: expected,
                        found_byte: b,
                    };
                }
            }
            PatternCheckResult::Passed
        }
        ExpectedPattern::Random => PatternCheckResult::NotApplicable,
    }
}

/// Aggregate pattern check result across multiple samples.
#[derive(Debug, Clone)]
pub struct PatternScanResult {
    pub blocks_checked: usize,
    pub blocks_passed: usize,
    pub violations: Vec<PatternCheckResult>,
    pub overall_passed: bool,
}

pub fn scan_pattern(
    samples: &[(u64, &[u8])],
    pattern: &ExpectedPattern,
) -> PatternScanResult {
    if matches!(pattern, ExpectedPattern::Random) {
        return PatternScanResult {
            blocks_checked: samples.len(),
            blocks_passed: samples.len(),
            violations: vec![],
            overall_passed: true,
        };
    }

    let mut violations = vec![];
    let mut passed = 0;

    for &(lba, data) in samples {
        let result = check_block_pattern(lba, data, pattern);
        if result == PatternCheckResult::Passed {
            passed += 1;
        } else {
            violations.push(result);
        }
    }

    PatternScanResult {
        blocks_checked: samples.len(),
        blocks_passed: passed,
        violations,
        overall_passed: passed == samples.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_pattern_pass() {
        let data = vec![0x00u8; 512];
        let result = check_block_pattern(0, &data, &ExpectedPattern::Zero);
        assert_eq!(result, PatternCheckResult::Passed);
    }

    #[test]
    fn test_zero_pattern_fail() {
        let mut data = vec![0x00u8; 512];
        data[100] = 0xAB;
        let result = check_block_pattern(42, &data, &ExpectedPattern::Zero);
        assert!(matches!(result, PatternCheckResult::Failed { first_violation_lba: 42, expected_byte: 0x00, found_byte: 0xAB }));
    }

    #[test]
    fn test_alternating_pattern_pass() {
        let data: Vec<u8> = (0..512).map(|i| if i % 2 == 0 { 0x55 } else { 0xAA }).collect();
        let result = check_block_pattern(0, &data, &ExpectedPattern::Alternating55AA);
        assert_eq!(result, PatternCheckResult::Passed);
    }

    #[test]
    fn test_random_pattern_not_applicable() {
        let data = vec![0x42u8; 512];
        let result = check_block_pattern(0, &data, &ExpectedPattern::Random);
        assert_eq!(result, PatternCheckResult::NotApplicable);
    }
}
