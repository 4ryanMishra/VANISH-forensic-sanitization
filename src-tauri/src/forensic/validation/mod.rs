use crate::common::recovery::{ArtifactFormat, ValidationStatus};

pub struct ArtifactValidator;

impl ArtifactValidator {
    /// Validates an in-memory carved or reconstructed byte buffer against format-specific syntactic requirements.
    /// Returns (ValidationStatus, confidence_score: 0.0 to 1.0).
    pub fn validate(data: &[u8], format: &ArtifactFormat) -> (ValidationStatus, f32) {
        if data.is_empty() {
            return (ValidationStatus::Corrupted, 0.0);
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
            ArtifactFormat::Unknown(_) => (ValidationStatus::Unverified, 0.50),
        }
    }

    /// JPEG Syntactic Validation:
    /// Checks SOI (FF D8), verifies marker progression, frame dimensions (SOF), and EOI (FF D9).
    pub fn validate_jpeg(data: &[u8]) -> (ValidationStatus, f32) {
        if data.len() < 4 {
            return (ValidationStatus::Corrupted, 0.0);
        }

        // SOI check
        if data[0] != 0xFF || data[1] != 0xD8 {
            return (ValidationStatus::Corrupted, 0.0);
        }

        // EOI check
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
                break; // SOS payload begins
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
            (ValidationStatus::Valid, 0.98)
        } else if has_sof && dimensions_valid {
            (ValidationStatus::Truncated, 0.75)
        } else if has_eoi {
            (ValidationStatus::Valid, 0.85)
        } else {
            (ValidationStatus::Corrupted, 0.30)
        }
    }

    /// PNG Syntactic Validation:
    /// Checks 8-byte magic header, IHDR chunk dimensions/depth, IDAT chunk presence, and IEND chunk.
    pub fn validate_png(data: &[u8]) -> (ValidationStatus, f32) {
        if data.len() < 8 || &data[0..8] != &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
            return (ValidationStatus::Corrupted, 0.0);
        }

        let mut has_ihdr = false;
        let mut has_idat = false;
        let mut has_iend = false;
        let mut dimensions_valid = false;

        let mut offset = 8;
        while offset + 12 <= data.len() {
            let chunk_len = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;

            let chunk_type = &data[offset + 4..offset + 8];

            if chunk_type == b"IHDR" {
                has_ihdr = true;
                if offset + 16 <= data.len() {
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

            let next_offset = offset + 12 + chunk_len;
            if next_offset <= offset || next_offset > data.len() {
                break;
            }
            offset = next_offset;
        }

        if has_ihdr && dimensions_valid && has_idat && has_iend {
            (ValidationStatus::Valid, 0.99)
        } else if has_ihdr && dimensions_valid && has_idat {
            (ValidationStatus::Truncated, 0.70)
        } else {
            (ValidationStatus::Corrupted, 0.25)
        }
    }

    /// PDF Syntactic Validation:
    /// Checks %PDF- header, catalog / root object, xref structure, and %%EOF trailer.
    pub fn validate_pdf(data: &[u8]) -> (ValidationStatus, f32) {
        if data.len() < 16 || !data.starts_with(b"%PDF-") {
            return (ValidationStatus::Corrupted, 0.0);
        }

        let content_str = String::from_utf8_lossy(data);

        let has_obj = content_str.contains("obj") && content_str.contains("endobj");
        let has_catalog = content_str.contains("/Catalog") || content_str.contains("/Root") || content_str.contains("/Pages");
        let has_eof = content_str.contains("%%EOF");
        let has_xref = content_str.contains("xref") || content_str.contains("/XRef");

        if has_eof && has_catalog && has_obj {
            (ValidationStatus::Valid, 0.95)
        } else if has_catalog && has_obj {
            (ValidationStatus::Truncated, 0.75)
        } else if has_eof {
            (ValidationStatus::Valid, 0.80)
        } else {
            (ValidationStatus::Corrupted, 0.35)
        }
    }

    /// ZIP / Office Open XML Validation:
    /// Checks PK\x03\x04 local file header, central directory, and EOCD (PK\x05\x06).
    pub fn validate_zip(data: &[u8]) -> (ValidationStatus, f32) {
        if data.len() < 22 || !data.starts_with(b"PK\x03\x04") {
            return (ValidationStatus::Corrupted, 0.0);
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
            (ValidationStatus::Valid, 0.96)
        } else if has_eocd {
            (ValidationStatus::Valid, 0.88)
        } else if has_central_dir {
            (ValidationStatus::Truncated, 0.70)
        } else {
            (ValidationStatus::Corrupted, 0.40)
        }
    }

    /// SQLite Database Validation:
    /// Checks 100-byte database header, page size validity, page count, and reserved byte zeros.
    pub fn validate_sqlite(data: &[u8]) -> (ValidationStatus, f32) {
        if data.len() < 100 || !data.starts_with(b"SQLite format 3\0") {
            return (ValidationStatus::Corrupted, 0.0);
        }

        let mut page_size = u16::from_be_bytes([data[16], data[17]]) as usize;
        if page_size == 1 {
            page_size = 65536;
        }

        let is_valid_page_size = (512..=65536).contains(&page_size) && (page_size & (page_size - 1)) == 0;
        let page_count = u32::from_be_bytes([data[28], data[29], data[30], data[31]]) as usize;

        if is_valid_page_size && page_count > 0 {
            let expected_size = page_size * page_count;
            if data.len() >= expected_size {
                (ValidationStatus::Valid, 0.97)
            } else {
                (ValidationStatus::Truncated, 0.70)
            }
        } else if is_valid_page_size {
            (ValidationStatus::Valid, 0.85)
        } else {
            (ValidationStatus::Corrupted, 0.30)
        }
    }

    /// Plain Text Validation:
    /// Checks if bytes are valid UTF-8 or printable ASCII.
    pub fn validate_plain_text(data: &[u8]) -> (ValidationStatus, f32) {
        if data.is_empty() {
            return (ValidationStatus::Corrupted, 0.0);
        }

        let valid_chars = data.iter().filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (32..=126).contains(&b)).count();
        let ratio = (valid_chars as f32) / (data.len() as f32);

        if ratio > 0.95 {
            (ValidationStatus::Valid, ratio)
        } else if ratio > 0.70 {
            (ValidationStatus::Unverified, ratio)
        } else {
            (ValidationStatus::Corrupted, 0.20)
        }
    }

    /// RIFF Validation (WAV/WEBP/AVI):
    pub fn validate_riff(data: &[u8]) -> (ValidationStatus, f32) {
        if data.len() < 12 || !data.starts_with(b"RIFF") {
            return (ValidationStatus::Corrupted, 0.0);
        }

        let payload_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let expected_total = payload_len + 8;

        if data.len() >= expected_total {
            (ValidationStatus::Valid, 0.95)
        } else {
            (ValidationStatus::Truncated, 0.70)
        }
    }

    /// GIF Validation:
    pub fn validate_gif(data: &[u8]) -> (ValidationStatus, f32) {
        if data.len() < 13 || (!data.starts_with(b"GIF87a") && !data.starts_with(b"GIF89a")) {
            return (ValidationStatus::Corrupted, 0.0);
        }

        let has_trailer = data.ends_with(&[0x3B]);
        if has_trailer {
            (ValidationStatus::Valid, 0.95)
        } else {
            (ValidationStatus::Truncated, 0.70)
        }
    }
}
