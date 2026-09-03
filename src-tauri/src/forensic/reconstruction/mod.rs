use crate::common::recovery::{ArtifactFormat, ValidationStatus};
use crate::forensic::carving::signature::{get_signature_for_format, KNOWN_SIGNATURES};
use crate::forensic::validation::ArtifactValidator;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentCandidate {
    pub start_offset: u64,
    pub length: usize,
    pub format: ArtifactFormat,
    pub is_head: bool,
    pub is_tail: bool,
    pub entropy: f64,
    pub raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructionHypothesis {
    pub head_offset: u64,
    pub head_len: usize,
    pub tail_offset: u64,
    pub tail_len: usize,
    pub gap_clusters: usize,
    pub confidence_score: f32,
    pub stitched_size: usize,
}

pub struct FragmentReconstructor;

impl FragmentReconstructor {
    /// Computes Shannon entropy (0.0 to 8.0 bits/byte) of a byte slice.
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0usize; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let len_f = data.len() as f64;
        let mut entropy = 0.0f64;

        for &count in &freq {
            if count > 0 {
                let p = (count as f64) / len_f;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Calculates entropy across contiguous blocks (e.g. 512B or 4096B sectors).
    pub fn block_entropy_map(data: &[u8], block_size: usize) -> Vec<(u64, f64)> {
        let mut map = Vec::new();
        let mut offset = 0u64;

        for chunk in data.chunks(block_size) {
            let ent = Self::calculate_entropy(chunk);
            map.push((offset, ent));
            offset += chunk.len() as u64;
        }

        map
    }

    /// Detects orphan fragment candidates within a storage stream.
    pub fn detect_orphan_fragments(
        data: &[u8],
        base_offset: u64,
        cluster_size: usize,
    ) -> Vec<FragmentCandidate> {
        let mut fragments = Vec::new();
        let min_cluster = if cluster_size == 0 { 4096 } else { cluster_size };

        let mut i = 0;
        while i < data.len() {
            let slice = &data[i..];

            // 1. Check for Header Candidates
            for sig in KNOWN_SIGNATURES {
                let hlen = sig.header.len();
                if slice.len() >= hlen && &slice[..hlen] == sig.header {
                    let mut has_contiguous_footer = false;
                    if let Some(footer) = sig.footer {
                        let flen = footer.len();
                        let max_search = slice.len().min(sig.max_size_bytes as usize);
                        for j in hlen..=(max_search.saturating_sub(flen)) {
                            if &slice[j..j + flen] == footer {
                                has_contiguous_footer = true;
                                break;
                            }
                        }
                    }

                    if !has_contiguous_footer {
                        let chunk_len = slice.len().min(min_cluster * 4);
                        let frag_bytes = slice[..chunk_len].to_vec();
                        let entropy = Self::calculate_entropy(&frag_bytes);

                        fragments.push(FragmentCandidate {
                            start_offset: base_offset + i as u64,
                            length: chunk_len,
                            format: sig.format.clone(),
                            is_head: true,
                            is_tail: false,
                            entropy,
                            raw_bytes: frag_bytes,
                        });
                    }
                }
            }

            // 2. Check for Tail Candidates
            for sig in KNOWN_SIGNATURES {
                if let Some(footer) = sig.footer {
                    let flen = footer.len();
                    if slice.len() >= flen && &slice[..flen] == footer {
                        let tail_start = i.saturating_sub(min_cluster);
                        let tail_bytes = data[tail_start..i + flen].to_vec();
                        let entropy = Self::calculate_entropy(&tail_bytes);

                        fragments.push(FragmentCandidate {
                            start_offset: base_offset + tail_start as u64,
                            length: tail_bytes.len(),
                            format: sig.format.clone(),
                            is_head: false,
                            is_tail: true,
                            entropy,
                            raw_bytes: tail_bytes,
                        });
                    }
                }
            }

            i += min_cluster;
        }

        fragments
    }

    /// Performs Bi-Fragment Gap Analysis with Sector Alignment & Format-Aware Parser Validation:
    /// Takes an orphan head fragment and searches downstream cluster offsets for matching candidate tails.
    /// Runs format-aware parser validation on candidate stitched buffers to verify structural validity.
    pub fn stitch_bi_fragment(
        head: &FragmentCandidate,
        search_space: &[u8],
        search_base_offset: u64,
        cluster_size: usize,
    ) -> Option<(Vec<u8>, ReconstructionHypothesis)> {
        let cluster = if cluster_size == 0 { 4096 } else { cluster_size };
        let sig = get_signature_for_format(&head.format)?;
        let footer = sig.footer?;

        let head_end_in_search = if head.start_offset >= search_base_offset {
            (head.start_offset - search_base_offset) as usize + head.length
        } else {
            0
        };

        if head_end_in_search >= search_space.len() {
            return None;
        }

        let max_gap_clusters = 16; // Search up to 16 clusters gap
        let flen = footer.len();

        for gap in 1..=max_gap_clusters {
            let gap_bytes = gap * cluster;
            let candidate_tail_start = head_end_in_search + gap_bytes;

            if candidate_tail_start + flen > search_space.len() {
                break;
            }

            // Search within this candidate cluster run for footer
            let search_window_end = (candidate_tail_start + (cluster * 4)).min(search_space.len());
            for k in candidate_tail_start..=(search_window_end.saturating_sub(flen)) {
                if &search_space[k..k + flen] == footer {
                    let tail_end = k + flen;
                    let tail_len = tail_end - candidate_tail_start;

                    let mut stitched = Vec::with_capacity(head.length + tail_len);
                    stitched.extend_from_slice(&head.raw_bytes);
                    stitched.extend_from_slice(&search_space[candidate_tail_start..tail_end]);

                    // Verify stitched size matches format expectations
                    if stitched.len() >= sig.min_size_bytes as usize && (stitched.len() as u64) <= sig.max_size_bytes {
                        // Structural parser verification on stitched buffer
                        let (val_status, val_conf) = ArtifactValidator::validate(&stitched, &head.format);
                        if val_status == ValidationStatus::Valid || val_status == ValidationStatus::Truncated {
                            let hypothesis = ReconstructionHypothesis {
                                head_offset: head.start_offset,
                                head_len: head.length,
                                tail_offset: search_base_offset + candidate_tail_start as u64,
                                tail_len,
                                gap_clusters: gap,
                                confidence_score: (0.90 - (gap as f32 * 0.02)) * val_conf,
                                stitched_size: stitched.len(),
                            };

                            return Some((stitched, hypothesis));
                        }
                    }
                }
            }
        }

        None
    }
}

