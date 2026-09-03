use crate::common::recovery::{ArtifactFormat, ValidationStatus};

/// IEEE 802.3 standard CRC32 checksum calculation for format validation (e.g. PNG chunk integrity)
pub fn calculate_crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        let mut b = (crc ^ (byte as u32)) & 0xFF;
        for _ in 0..8 {
            if (b & 1) != 0 {
                b = (b >> 1) ^ 0xEDB8_8320;
            } else {
                b >>= 1;
            }
        }
        crc = (crc >> 8) ^ b;
    }
    !crc
}

pub struct ValidationOutcome {
    pub status: ValidationStatus,
    pub confidence_score: f32,
    pub validation_method: &'static str,
    pub detail: String,
}

pub struct ArtifactValidator;

impl ArtifactValidator {
    /// Validates an in-memory carved or reconstructed byte buffer against format-specific syntactic requirements.
    /// Returns (ValidationStatus, confidence_score: 0.0 to 1.0).
    pub fn validate(data: &[u8], format: &ArtifactFormat) -> (ValidationStatus, f32) {
        let outcome = Self::validate_detailed(data, format);
        (outcome.status, outcome.confidence_score)
    }

    /// Detailed validation returning method name and structural diagnostics.
    pub fn validate_detailed(data: &[u8], format: &ArtifactFormat) -> ValidationOutcome {
        if data.is_empty() {
            return ValidationOutcome {
                status: ValidationStatus::Corrupted,
                confidence_score: 0.0,
                validation_method: "Empty Buffer Check",
                detail: "Target buffer is zero bytes.".to_string(),
            };
        }

        match format {
            ArtifactFormat::Jpeg => Self::validate_jpeg(data),
            ArtifactFormat::Png => Self::validate_png(data),
            ArtifactFormat::Pdf => Self::validate_pdf(data),
            ArtifactFormat::Zip => Self::validate_zip(data),
            ArtifactFormat::Sqlite => Self::validate_sqlite(data),
            ArtifactFormat::PlainText => Self::validate_plain_text(data),
            ArtifactFormat::Unknown(tag) if tag == "RIFF" => Self::validate_riff(data),
            ArtifactFormat::Unknown(tag) if tag == "GIF" => Self::validate_gif(data),
            ArtifactFormat::Unknown(_) => ValidationOutcome {
                status: ValidationStatus::Unverified,
                confidence_score: 0.50,
                validation_method: "Generic Magic Byte Check",
                detail: "Unknown container format; structural validator unavailable.".to_string(),
            },
        }
    }

    /// JPEG Syntactic Validation:
    /// Checks SOI (FF D8), verifies marker progression, frame dimensions (SOF0/SOF2), SOS payload, and EOI (FF D9).
    pub fn validate_jpeg(data: &[u8]) -> ValidationOutcome {
        if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
            return ValidationOutcome {
                status: ValidationStatus::Corrupted,
                confidence_score: 0.0,
                validation_method: "JPEG SOI Marker Inspection",
                detail: "Missing JPEG Start-of-Image (SOI 0xFFD8) magic.".to_string(),
            };
        }

        // Verify second marker is valid (APP0..APP15: E0..EF, DQT: DB, SOF: C0/C2, Comment: FE)
        let second_marker = data[2] == 0xFF && ((0xE0..=0xEF).contains(&data[3]) || data[3] == 0xDB || data[3] == 0xC0 || data[3] == 0xC2 || data[3] == 0xFE);
        if !second_marker {
            return ValidationOutcome {
                status: ValidationStatus::FalsePositive,
                confidence_score: 0.10,
                validation_method: "JPEG Marker Sequence Inspection",
                detail: "False candidate: SOI followed by non-JPEG marker bytes.".to_string(),
            };
        }

        let has_eoi = data.len() >= 2 && data[data.len() - 2] == 0xFF && data[data.len() - 1] == 0xD9;
        let mut has_sof = false;
        let mut has_sos = false;
        let mut dimensions_valid = false;
        let mut i = 2;

        while i + 4 <= data.len() {
            if data[i] != 0xFF {
                i += 1;
                continue;
            }

            let marker = data[i + 1];

            // Ignore byte stuffing (FF 00) or restart markers (RST0..RST7: D0..D7)
            if marker == 0x00 || (0xD0..=0xD7).contains(&marker) {
                i += 2;
                continue;
            }

            // EOI
            if marker == 0xD9 {
                break;
            }

            // Start of Scan
            if marker == 0xDA {
                has_sos = true;
                break; // SOS payload scan data begins
            }

            // Check SOF0 (Baseline) or SOF2 (Progressive)
            if marker == 0xC0 || marker == 0xC2 {
                has_sof = true;
                if i + 8 <= data.len() {
                    let height = u16::from_be_bytes([data[i + 5], data[i + 6]]);
                    let width = u16::from_be_bytes([data[i + 7], data[i + 8]]);
                    if width > 0 && height > 0 {
                        dimensions_valid = true;
                    }
                }
            }

            // Read marker segment length
            if i + 3 < data.len() {
                let seg_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
                if seg_len < 2 {
                    break;
                }
                i += 2 + seg_len;
            } else {
                break;
            }
        }

        if has_eoi && has_sof && dimensions_valid && has_sos {
            ValidationOutcome {
                status: ValidationStatus::Valid,
                confidence_score: 0.98,
                validation_method: "JPEG Complete Frame & Marker Stream Parser",
                detail: "Valid complete JPEG: SOI, SOF, SOS, and EOI markers verified with valid frame dimensions.".to_string(),
            }
        } else if has_sof && dimensions_valid {
            ValidationOutcome {
                status: ValidationStatus::Truncated,
                confidence_score: 0.75,
                validation_method: "JPEG Frame Header Parser",
                detail: "Truncated JPEG: Valid SOF frame dimensions, but missing EOI trailer.".to_string(),
            }
        } else if has_eoi {
            ValidationOutcome {
                status: ValidationStatus::Valid,
                confidence_score: 0.85,
                validation_method: "JPEG Bounded Stream Inspection",
                detail: "Valid JPEG stream bounded by SOI and EOI markers.".to_string(),
            }
        } else {
            ValidationOutcome {
                status: ValidationStatus::Corrupted,
                confidence_score: 0.25,
                validation_method: "JPEG Structural Parser",
                detail: "Corrupted JPEG stream: Markers broken or payload incomplete.".to_string(),
            }
        }
    }

    /// PNG Syntactic Validation with CRC32 Chunk Integrity Verification:
    pub fn validate_png(data: &[u8]) -> ValidationOutcome {
        if data.len() < 8 || &data[0..8] != &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
            return ValidationOutcome {
                status: ValidationStatus::Corrupted,
                confidence_score: 0.0,
                validation_method: "PNG 8-Byte Magic Header Check",
                detail: "Missing canonical PNG magic bytes (0x89504E470D0A1A0A).".to_string(),
            };
        }

        let mut has_ihdr = false;
        let mut has_idat = false;
        let mut has_iend = false;
        let mut dimensions_valid = false;
        let mut crc_failed = false;

        let mut offset = 8;
        while offset + 12 <= data.len() {
            let chunk_len = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;

            let chunk_type = &data[offset + 4..offset + 8];

            if offset + 12 + chunk_len > data.len() {
                // Chunk extends beyond buffer
                break;
            }

            // Verify Chunk CRC32
            let chunk_data_range = &data[offset + 4..offset + 8 + chunk_len];
            let calculated_crc = calculate_crc32(chunk_data_range);
            let expected_crc = u32::from_be_bytes([
                data[offset + 8 + chunk_len],
                data[offset + 9 + chunk_len],
                data[offset + 10 + chunk_len],
                data[offset + 11 + chunk_len],
            ]);

            if calculated_crc != expected_crc {
                crc_failed = true;
                break;
            }

            if chunk_type == b"IHDR" {
                has_ihdr = true;
                if chunk_len >= 13 && offset + 20 <= data.len() {
                    let width = u32::from_be_bytes([data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11]]);
                    let height = u32::from_be_bytes([data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15]]);
                    if width > 0 && height > 0 {
                        dimensions_valid = true;
                    }
                }
            } else if chunk_type == b"IDAT" {
                has_idat = true;
            } else if chunk_type == b"IEND" {
                has_iend = true;
                break;
            }

            offset += 12 + chunk_len;
        }

        if crc_failed {
            ValidationOutcome {
                status: ValidationStatus::Corrupted,
                confidence_score: 0.15,
                validation_method: "PNG Chunk CRC32 Integrity Verification",
                detail: "Corrupted PNG: Chunk CRC32 checksum mismatch detected.".to_string(),
            }
        } else if has_ihdr && dimensions_valid && has_idat && has_iend {
            ValidationOutcome {
                status: ValidationStatus::Valid,
                confidence_score: 0.99,
                validation_method: "PNG Chunk Sequence & CRC32 Validator",
                detail: "Valid complete PNG: IHDR, IDAT, and IEND chunks verified with 100% matching CRC32 checksums.".to_string(),
            }
        } else if has_ihdr && dimensions_valid && has_idat {
            ValidationOutcome {
                status: ValidationStatus::Truncated,
                confidence_score: 0.70,
                validation_method: "PNG Chunk Header Validator",
                detail: "Truncated PNG: Valid IHDR and IDAT chunks with valid CRCs, but missing IEND chunk.".to_string(),
            }
        } else {
            ValidationOutcome {
                status: ValidationStatus::FalsePositive,
                confidence_score: 0.10,
                validation_method: "PNG Structural Validator",
                detail: "False candidate: PNG header present without valid IHDR structure.".to_string(),
            }
        }
    }

    /// PDF Syntactic Validation:
    /// Checks %PDF- header, catalog / root object, xref structure, and %%EOF trailer.
    pub fn validate_pdf(data: &[u8]) -> ValidationOutcome {
        if data.len() < 16 || !data.starts_with(b"%PDF-") {
            return ValidationOutcome {
                status: ValidationStatus::Corrupted,
                confidence_score: 0.0,
                validation_method: "PDF Magic Header Check",
                detail: "Missing %PDF- header.".to_string(),
            };
        }

        let content_str = String::from_utf8_lossy(data);

        let has_obj = content_str.contains("obj") && content_str.contains("endobj");
        let has_catalog = content_str.contains("/Catalog") || content_str.contains("/Root") || content_str.contains("/Pages");
        let has_eof = content_str.contains("%%EOF");
        let has_xref = content_str.contains("xref") || content_str.contains("/XRef");

        if !has_obj && !has_catalog && !has_xref {
            return ValidationOutcome {
                status: ValidationStatus::FalsePositive,
                confidence_score: 0.10,
                validation_method: "PDF Structural Object Parser",
                detail: "False candidate: %PDF- string found in non-PDF text without valid object definitions.".to_string(),
            };
        }

        if has_eof && has_catalog && has_obj {
            ValidationOutcome {
                status: ValidationStatus::Valid,
                confidence_score: 0.96,
                validation_method: "PDF Object Catalog & Trailer Parser",
                detail: "Valid complete PDF: Catalog, object hierarchy, and %%EOF trailer confirmed.".to_string(),
            }
        } else if has_catalog && has_obj {
            ValidationOutcome {
                status: ValidationStatus::Truncated,
                confidence_score: 0.75,
                validation_method: "PDF Object Parser",
                detail: "Truncated PDF: Object catalog present but missing %%EOF trailer.".to_string(),
            }
        } else if has_eof {
            ValidationOutcome {
                status: ValidationStatus::Valid,
                confidence_score: 0.80,
                validation_method: "PDF Trailer Validator",
                detail: "Valid PDF: %%EOF trailer confirmed.".to_string(),
            }
        } else {
            ValidationOutcome {
                status: ValidationStatus::Corrupted,
                confidence_score: 0.30,
                validation_method: "PDF Parser",
                detail: "Corrupted PDF document stream.".to_string(),
            }
        }
    }

    /// ZIP / Office Open XML Validation:
    pub fn validate_zip(data: &[u8]) -> ValidationOutcome {
        if data.len() < 22 || !data.starts_with(b"PK\x03\x04") {
            return ValidationOutcome {
                status: ValidationStatus::Corrupted,
                confidence_score: 0.0,
                validation_method: "ZIP Local File Header Check",
                detail: "Missing PK\\x03\\x04 local header magic.".to_string(),
            };
        }

        let mut has_eocd = false;
        let mut has_central_dir = false;

        for i in 0..=(data.len().saturating_sub(4)) {
            if &data[i..i + 4] == b"PK\x01\x02" {
                has_central_dir = true;
            } else if &data[i..i + 4] == b"PK\x05\x06" {
                has_eocd = true;
            }
        }

        if has_eocd && has_central_dir {
            ValidationOutcome {
                status: ValidationStatus::Valid,
                confidence_score: 0.96,
                validation_method: "ZIP Central Directory & EOCD Validator",
                detail: "Valid ZIP archive: Local header, Central Directory, and EOCD confirmed.".to_string(),
            }
        } else if has_eocd {
            ValidationOutcome {
                status: ValidationStatus::Valid,
                confidence_score: 0.88,
                validation_method: "ZIP EOCD Validator",
                detail: "Valid ZIP archive: End of Central Directory record confirmed.".to_string(),
            }
        } else if has_central_dir {
            ValidationOutcome {
                status: ValidationStatus::Truncated,
                confidence_score: 0.70,
                validation_method: "ZIP Central Directory Check",
                detail: "Truncated ZIP archive: Central Directory present without EOCD.".to_string(),
            }
        } else {
            ValidationOutcome {
                status: ValidationStatus::Corrupted,
                confidence_score: 0.35,
                validation_method: "ZIP Structural Parser",
                detail: "Corrupted ZIP container.".to_string(),
            }
        }
    }

    /// SQLite Database Validation:
    pub fn validate_sqlite(data: &[u8]) -> ValidationOutcome {
        if data.len() < 100 || !data.starts_with(b"SQLite format 3\0") {
            return ValidationOutcome {
                status: ValidationStatus::Corrupted,
                confidence_score: 0.0,
                validation_method: "SQLite Magic Header Check",
                detail: "Missing SQLite format 3\\0 16-byte magic.".to_string(),
            };
        }

        let mut page_size = u16::from_be_bytes([data[16], data[17]]) as usize;
        if page_size == 1 {
            page_size = 65536;
        }

        let is_valid_page_size = (512..=65536).contains(&page_size) && (page_size & (page_size - 1)) == 0;
        let page_count = u32::from_be_bytes([data[28], data[29], data[30], data[31]]) as usize;

        if !is_valid_page_size {
            return ValidationOutcome {
                status: ValidationStatus::FalsePositive,
                confidence_score: 0.10,
                validation_method: "SQLite Header Parser",
                detail: "False candidate: Invalid page size in SQLite header.".to_string(),
            };
        }

        if page_count > 0 {
            let expected_size = page_size * page_count;
            if data.len() >= expected_size {
                ValidationOutcome {
                    status: ValidationStatus::Valid,
                    confidence_score: 0.97,
                    validation_method: "SQLite 100-Byte Header & Page Table Validator",
                    detail: format!("Valid complete SQLite database: page_size={}, page_count={}.", page_size, page_count),
                }
            } else {
                ValidationOutcome {
                    status: ValidationStatus::Truncated,
                    confidence_score: 0.70,
                    validation_method: "SQLite Header Validator",
                    detail: format!("Truncated SQLite database: expected {} bytes, received {}.", expected_size, data.len()),
                }
            }
        } else {
            ValidationOutcome {
                status: ValidationStatus::Valid,
                confidence_score: 0.85,
                validation_method: "SQLite Header Validator",
                detail: format!("Valid SQLite database header: page_size={}.", page_size),
            }
        }
    }

    /// Plain Text Validation:
    pub fn validate_plain_text(data: &[u8]) -> ValidationOutcome {
        if data.is_empty() {
            return ValidationOutcome {
                status: ValidationStatus::Corrupted,
                confidence_score: 0.0,
                validation_method: "Plain Text UTF-8/ASCII Validator",
                detail: "Empty text buffer.".to_string(),
            };
        }

        let valid_chars = data.iter().filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (32..=126).contains(&b)).count();
        let ratio = (valid_chars as f32) / (data.len() as f32);

        if ratio > 0.95 {
            ValidationOutcome {
                status: ValidationStatus::Valid,
                confidence_score: ratio,
                validation_method: "Plain Text UTF-8/ASCII Validator",
                detail: format!("Valid UTF-8/ASCII plain text ({:.1}% printable).", ratio * 100.0),
            }
        } else if ratio > 0.70 {
            ValidationOutcome {
                status: ValidationStatus::Unverified,
                confidence_score: ratio,
                validation_method: "Plain Text Validator",
                detail: "Unverified text with binary components.".to_string(),
            }
        } else {
            ValidationOutcome {
                status: ValidationStatus::Corrupted,
                confidence_score: 0.20,
                validation_method: "Plain Text Validator",
                detail: "Corrupted text buffer containing high density of non-printable bytes.".to_string(),
            }
        }
    }

    /// RIFF Validation:
    pub fn validate_riff(data: &[u8]) -> ValidationOutcome {
        if data.len() < 12 || !data.starts_with(b"RIFF") {
            return ValidationOutcome {
                status: ValidationStatus::Corrupted,
                confidence_score: 0.0,
                validation_method: "RIFF Container Header Check",
                detail: "Missing RIFF header magic.".to_string(),
            };
        }

        let payload_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let expected_total = payload_len + 8;

        if data.len() >= expected_total {
            ValidationOutcome {
                status: ValidationStatus::Valid,
                confidence_score: 0.95,
                validation_method: "RIFF Chunk Size Validator",
                detail: format!("Valid complete RIFF container: {} bytes total.", expected_total),
            }
        } else {
            ValidationOutcome {
                status: ValidationStatus::Truncated,
                confidence_score: 0.70,
                validation_method: "RIFF Header Validator",
                detail: format!("Truncated RIFF container: expected {} bytes, received {}.", expected_total, data.len()),
            }
        }
    }

    /// GIF Validation:
    pub fn validate_gif(data: &[u8]) -> ValidationOutcome {
        if data.len() < 13 || (!data.starts_with(b"GIF87a") && !data.starts_with(b"GIF89a")) {
            return ValidationOutcome {
                status: ValidationStatus::Corrupted,
                confidence_score: 0.0,
                validation_method: "GIF Header Magic Check",
                detail: "Missing GIF87a/GIF89a magic.".to_string(),
            };
        }

        let has_trailer = data.ends_with(&[0x3B]);
        if has_trailer {
            ValidationOutcome {
                status: ValidationStatus::Valid,
                confidence_score: 0.95,
                validation_method: "GIF Trailer & Header Validator",
                detail: "Valid complete GIF image with 0x3B trailer.".to_string(),
            }
        } else {
            ValidationOutcome {
                status: ValidationStatus::Truncated,
                confidence_score: 0.70,
                validation_method: "GIF Header Validator",
                detail: "Truncated GIF image without 0x3B trailer.".to_string(),
            }
        }
    }
}

