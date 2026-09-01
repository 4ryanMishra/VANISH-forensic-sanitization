/// Computes Shannon entropy over a byte slice: value ranges from 0.0 (uniform bytes) to 8.0 (pure random)
pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &c in counts.iter() {
        if c > 0 {
            let p = (c as f64) / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_entropy_for_uniform_buffer() {
        let zeroes = vec![0u8; 4096];
        assert_eq!(calculate_shannon_entropy(&zeroes), 0.0);
    }
}
