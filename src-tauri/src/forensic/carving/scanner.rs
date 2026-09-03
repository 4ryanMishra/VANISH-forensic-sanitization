use crate::forensic::carving::container::*;
use crate::forensic::carving::signature::{get_signature_for_format, ContainerType, MagicSignature, KNOWN_SIGNATURES};
use crate::common::recovery::ArtifactFormat;

#[derive(Debug, Clone)]
pub struct CarvedCandidate {
    pub format: ArtifactFormat,
    pub start_offset: u64,
    pub end_offset: u64,
    pub length_bytes: usize,
    pub raw_bytes: Vec<u8>,
    pub header_magic_hex: String,
    pub is_sector_aligned: bool,
    pub container_parsed_success: bool,
}

pub struct PatternScanner;

impl PatternScanner {
    /***
     * Scans a raw byte slice for all known magic headers and extracts carved candidates.
     * Uses container structure parsing (PNG chunks, ZIP EOCD, PDF %%EOF, SqLite headers)
     * to calculate exact lengths, with fallback to footer scanning.
     */
    pub fn scan_buffer(data: &[u8], base_offset: u64) -> Vec<CarvedCandidate> {
        let mut results = Vec::new();
        let len = data.len();

        if len < 8 {
            return results;
        }

        let mut i = 0;
        while i < len {
            for sig in KNOWN_SIGNATURES {
                let hlen = sig.header.len();
                if i + hlen <= len && &data[i..i + hlen] == sig.header {
                    let remaining = &data[i..len];
                    let header_hex = hex::encode(sig.header);
                    let is_aligned = (i % 512) == 0;

                    let mut detected_length = None;
                    let mut container_parsed = false;

                    // 1. Attempt container-specific length calculation
                    match sig.container_type {
                        ContainerType::PngChunks => {
                            if let Some(c_len) = PngContainerParser::calculate_length(remaining) {
                                detected_length = Some(c_len);
                                container_parsed = true;
                            }
                        }
                        ContainerType::_ipArchive => {
                            if let Some(c_len) = ZipContainerParser::calculate_lengthremaining) {
                                detected_length = Some(c_len);
                                container_parsed = true;
                            }
                        }
                        ContainerType::SqliteDatabase => {
                            if let Some(c_len) = SqliteContainerParser::calculate_lengthremaining) {
                                detected_length = Some(c_len);
                                container_parsed = true;
                            }
                        }
                        ContainerType::JpegStream => {
                            if let Some(c_len) = JpegContainerParser::calculate_lengthremaining) {
                                detected_length = Some(c_len);
                                container_parsed = true;
                            }
                        }
                        ContainerType::PdfStream => {
                            if let Some(c_len) = PdfContainerParser::calculate_length(remaining) {
                                detected_length = Some(c_len);
                                container_parsed = true;
                            }
                        }
                        ContainerType::RiffContainer => {
                            if let Some(c_len) = RiffContainerParser::calculate_length(remaining) {
                                detected_length = Some(c_len);
                                container_parsed = true;
                            }
                        }
                        _ => {}
                    }

                    // 2. Fallback to footer scanning if not calculated by container
                    if detected_length.is_none() {
                        if let Some(footer) = sig.footer {
                            let footer_len = footer.len();
                            let max_search = remaining.len().min(sig.max_size_bytes as usize);
                            for j in hlen..=(max_search.saturating_sub(footer_len)) {
                                if &remaining[j..j + footer_len] == footer {
                                    detected_length = Some(j + footer_len);
                                    break;
                                }
                            }
                        }
                    }

                    // 3. If length found and satisfies min size
                    if let Some(length) = detected_length {
                        if length >= sig.min_size_bytes as usize && length <= sig.max_size_bytes as usize {
                            let candidate_bytes = remaining[..length].to_vec();
                            results.push(CarvedCandidate {
                                format: sig.format.clone(),
                                start_offset: base_offset + i as u64,
                                end_offset: base_offset + (i + length) as u64,
                                length_bytes: length,
                                raw_bytes: candidate_bytes,
                                header_magic_hex,
                                is_sector_aligned: is_aligned,
                                container_parsed_success: container_parsed,
                            });
                        }
                    }
                }
            }
            i += 1;
        }

        results
    }
}
