use crate::common::recovery::{
    ArtifactFormat, ArtifactProvenance, CarvingMethod, FragmentRecord,
    RecoveredArtifact, ValidationStatus,
};
use crate::forensic::carving::scanner::PatternScanner;
use crate::forensic::imaging::RawImageReader;
use crate::forensic::reconstruction::FragmentReconstructor;
use crate::forensic::validation::ArtifactValidator;
use chrono::Utc;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicMetrics {
    pub total_scanned_bytes: u64,
    pub artifacts_found: usize,
    pub valid_count: usize,
    pub corrupted_count: usize,
    pub fragmented_count: usize,
    pub mean_entropy: f64,
}

pub struct ForensicEngine;

impl ForensicEngine {
    /// Comprehensive end-to-end forensic scan across an in-memory byte buffer.
    /// Executes signature carving, bi-fragment gap reconstruction, format-aware validation,
    /// and canonical SHA-256 provenance hashing.
    pub fn scan_bytes(data: &[u8], source_id: &str) -> Vec<RecoveredArtifact> {
        Self::scan_bytes_with_source_type(data, source_id, "SimulationBuffer")
    }

    /// Comprehensive forensic scan across an evidence source with explicit provenance source type.
    pub fn scan_bytes_with_source_type(data: &[u8], source_id: &str, source_type_desc: &str) -> Vec<RecoveredArtifact> {
        let mut artifacts = Vec::new();
        if data.is_empty() {
            return artifacts;
        }

        let now_utc = Utc::now().to_rfc3339();
        let source_hash = hex::encode(Sha256::digest(data));

        // 1. Contiguous Signature & Container Carving
        let carved_candidates = PatternScanner::scan_buffer(data, 0);
        let mut covered_ranges: Vec<(u64, u64)> = Vec::new();

        for cand in carved_candidates {
            let outcome = ArtifactValidator::validate_detailed(&cand.raw_bytes, &cand.format);

            // Filter out false candidates (e.g. magic byte found in random data without valid structure)
            if outcome.status == ValidationStatus::FalsePositive {
                continue;
            }

            // Real cryptographic hashes computed directly from the extracted artifact bytes
            let sha256 = hex::encode(Sha256::digest(&cand.raw_bytes));
            let b3_hash = blake3::hash(&cand.raw_bytes).to_hex().to_string();
            let entropy = FragmentReconstructor::calculate_entropy(&cand.raw_bytes);

            let start_sector = cand.start_offset / 512;
            let end_sector = (cand.end_offset + 511) / 512;
            covered_ranges.push((cand.start_offset, cand.end_offset));

            let art_id = format!("art-{}-{}", &sha256[..8], cand.start_offset);
            let ext = match &cand.format {
                ArtifactFormat::Jpeg => "jpg",
                ArtifactFormat::Png => "png",
                ArtifactFormat::Pdf => "pdf",
                ArtifactFormat::Zip => "zip",
                ArtifactFormat::Sqlite => "sqlite",
                ArtifactFormat::PlainText => "txt",
                ArtifactFormat::Gif => "gif",
                ArtifactFormat::Riff => "riff",
                ArtifactFormat::Unknown(ref t) => match t.as_str() {
                    "RIFF" => "wav",
                    "GIF" => "gif",
                    other => other,
                },
            };

            let fragment = FragmentRecord {
                sequence_index: 0,
                start_offset: cand.start_offset,
                length_bytes: cand.length_bytes,
                sector_start: start_sector,
                sector_end: end_sector,
            };

            artifacts.push(RecoveredArtifact {
                artifact_id: art_id.clone(),
                source_id: source_id.to_string(),
                source_hash: Some(source_hash.clone()),
                source_offsets: vec![(cand.start_offset, cand.end_offset)],
                format: cand.format.clone(),
                original_path: Some(format!("recovered/{}_carved.{}", art_id, ext)),
                extracted_path: Some(format!("recovered/{}_carved.{}", art_id, ext)),
                size_bytes: cand.length_bytes as u64,
                sha256,
                optional_blake3: Some(b3_hash),
                validation_status: outcome.status,
                validation_method: outcome.validation_method.to_string(),
                confidence_score: outcome.confidence_score,
                timestamp_utc: now_utc.clone(),
                provenance: ArtifactProvenance {
                    source_id: source_id.to_string(),
                    source_type_desc: source_type_desc.to_string(),
                    detection_method: CarvingMethod::ContiguousSignature,
                    validation_method: outcome.validation_method.to_string(),
                    sector_ranges: vec![(start_sector, end_sector)],
                    fragments: vec![fragment],
                    entropy_score: entropy,
                    header_magic: cand.header_magic_hex,
                    recovery_timestamp_utc: now_utc.clone(),
                },
            });
        }

        // 2. Bi-Fragment Gap Reconstruction (for orphan fragments)
        let orphans = FragmentReconstructor::detect_orphan_fragments(data, 0, 4096);
        for orphan in &orphans {
            if orphan.is_head {
                let already_covered = covered_ranges.iter().any(|(s, e)| orphan.start_offset >= *s && orphan.start_offset < *e);
                if !already_covered {
                    if let Some((stitched, hyp)) = FragmentReconstructor::stitch_bi_fragment(orphan, data, 0, 4096) {
                        let outcome = ArtifactValidator::validate_detailed(&stitched, &orphan.format);
                        if outcome.status != ValidationStatus::Corrupted && outcome.status != ValidationStatus::FalsePositive {
                            // Real cryptographic hashes computed directly from the stitched bytes
                            let sha256 = hex::encode(Sha256::digest(&stitched));
                            let b3_hash = blake3::hash(&stitched).to_hex().to_string();
                            let entropy = FragmentReconstructor::calculate_entropy(&stitched);
                            let art_id = format!("art-recon-{}-{}", &sha256[..8], hyp.head_offset);

                            let frag0 = FragmentRecord {
                                sequence_index: 0,
                                start_offset: hyp.head_offset,
                                length_bytes: hyp.head_len,
                                sector_start: hyp.head_offset / 512,
                                sector_end: (hyp.head_offset + hyp.head_len as u64 + 511) / 512,
                            };

                            let frag1 = FragmentRecord {
                                sequence_index: 1,
                                start_offset: hyp.tail_offset,
                                length_bytes: hyp.tail_len,
                                sector_start: hyp.tail_offset / 512,
                                sector_end: (hyp.tail_offset + hyp.tail_len as u64 + 511) / 512,
                            };

                            artifacts.push(RecoveredArtifact {
                                artifact_id: art_id.clone(),
                                source_id: source_id.to_string(),
                                source_hash: Some(source_hash.clone()),
                                source_offsets: vec![
                                    (hyp.head_offset, hyp.head_offset + hyp.head_len as u64),
                                    (hyp.tail_offset, hyp.tail_offset + hyp.tail_len as u64),
                                ],
                                format: orphan.format.clone(),
                                original_path: Some(format!("recovered/{}_reconstructed.pdf", art_id)),
                                extracted_path: Some(format!("recovered/{}_reconstructed.pdf", art_id)),
                                size_bytes: stitched.len() as u64,
                                sha256,
                                optional_blake3: Some(b3_hash),
                                validation_status: outcome.status,
                                validation_method: format!("Bi-Fragment Stitched & {}", outcome.validation_method),
                                confidence_score: hyp.confidence_score * outcome.confidence_score,
                                timestamp_utc: now_utc.clone(),
                                provenance: ArtifactProvenance {
                                    source_id: source_id.to_string(),
                                    source_type_desc: source_type_desc.to_string(),
                                    detection_method: CarvingMethod::FragmentedReconstruction,
                                    validation_method: format!("Bi-Fragment Stitched & {}", outcome.validation_method),
                                    sector_ranges: vec![
                                        (frag0.sector_start, frag0.sector_end),
                                        (frag1.sector_start, frag1.sector_end),
                                    ],
                                    fragments: vec![frag0, frag1],
                                    entropy_score: entropy,
                                    header_magic: "---FRAGMENT-STITCHED---".to_string(),
                                    recovery_timestamp_utc: now_utc.clone(),
                                },
                            });
                        }
                    }
                }
            }
        }

        artifacts
    }

    /// Read-only forensic image scanner (dd / img / raw image file)
    pub fn scan_image_file<P: AsRef<Path>>(path: P, source_id: &str) -> Result<Vec<RecoveredArtifact>, String> {
        let reader = RawImageReader::open(path.as_ref())
            .map_err(|e| format!("Failed to open forensic image in read-only mode: {}", e))?;
        let bytes = reader.read_all()
            .map_err(|e| format!("Failed to read forensic image: {}", e))?;
        Ok(Self::scan_bytes_with_source_type(&bytes, source_id, "ForensicImageFile"))
    }

    /// L4 Forensic Verification Check: Attempts to detect any recoverable files
    /// or recognizable structures from a sanitized byte stream.
    /// Returns `true` if 0 artifacts were recovered (no recognized artifacts detected).
    pub fn validate_target_absence(data: &[u8]) -> bool {
        let artifacts = Self::scan_bytes(data, "sanitized_verification_target");
        artifacts.is_empty()
    }
}
