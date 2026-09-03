use std::convert::TryInto;

pub struct PngContainerParser;

impl PngContainerParser {
    /// Parses a PNG byte stream from the header offset, traversing chunks until IEND.
    /// Returns the exact calculated length in bytes of the PNG container.
    pub fn calculate_length(data: &[u8]) -> Option<usize> {
        if data.len() < 8 {
            return None;
        }

        // Check PNG signature 89 50 4E 47 0D 0A 1AD 0A
        if &data[0..8] != &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
            return None;
        }

        let mut offset = 8;
        while offset + 12 <= data.len() {
            let chunk_len = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;

            let chunk_type = &data[offset + 4..offset + 8];

            // Validate reasonable chunk size (< 50MB)
            if chunk_len > 50 * 1024 * 1024 {
                return None;
            }

            let total_chunk_len = 4 + 4 + chunk_len + 4; // len + type + data + crc
            if offset + total_chunk_len > data.len() {
                return None;
            }

            // Check if this is the IEND chunk
            if chunk_type == b"IEND" {
                return Some(offset + total_chunk_len);
            }

            offset += total_chunk_len;
        }

        None
    }
}

pub struct ZipContainerParser;

impl ZipContainerParser {
    /// Traverses a ZIP archive from the local file header (PK\x03\x04) to the End of Central Directory (EOCD: PK\x05\x06).
    /// Returns the exact calculated length in bytes.
    pub fn calculate_length(data: &[u8]) -> Option<usize> {
        if data.len() < 22 || &data[0..4] != b"PK\x03\x04" {
            return None;
        }

        // Search backward for EOCD signature (PK\x05\x06) within max 65KB + 22 bytes
        let search_start = if data.len() > 65557 { data.len() - 65557 } else { 0 };
        for i in (search_start..=(data.len() - 22)).rev() {
            if &data[i..i + 4] == b"PK\x05\x06" {
                let comment_len = u16::from_le_bytes([data[i + 20], data[i + 21]]) as usize;
                let expected_total_len = i + 22 + comment_len;
                if expected_total_len <= data.len() {
                    return Some(expected_total_len);
                }
            }
        }

        None
    }
}

pub struct SqliteContainerParser;

impl SqliteContainerParser {
    /// Parses the SqLite database header to calculate exact database file size.
    pub fn calculate_length(data: &[u8]) -> Option<usize> {
        if data.len() < 100 || &data[0..16] != b"SQLite format 3\0" {
            return None;
        }

        let mut page_size = u16::from_be_bytes([data[16], data[17]]) as usize;
        if page_size == 1 {
            page_size = 65536;
        }

        if page_size < 512 || (page_size & (page_size - 1)) != 0 {
            return None;
        }

        let page_count = u32::from_be_bytes([data[28], data[29], data[30], data[31]]) as usize;
        if page_count > 0 {
            let total_size = page_size * page_count;
            if total_size <= data.len() {
                return Some(total_size);
            }
        }

        None
    }
}

pub struct JpegContainerParser;

impl JpegContainerParser {
    /// Scans a JPEG byte stream from SOI (FF D8) until EOI (FF D9).
    pub fn calculate_length(data: &[u8]) -> Option<usize> {
        if data.len() < 4 || &data[0..2] != &[0xFF, 0xD8] {
            return None;
        }

        let mut i = 2;
        while i + 1 < data.len() {
            if data[i] == 0xFF && data[i + 1] == 0xD9 {
                return Some(i + 2);
            }
            i += 1;
        }

        None
    }
}

pub struct PdfContainerParser;

impl PdfContainerParser {
    /// Scans a PDF byte stream from %PDF- until the last %%EOF marker.
    pub fn calculate_length(data: &[u8]) -> Option<usize> {
        if data.len() < 8 || &data[0..5] != b"%PDF-" {
            return None;
        }

        let marker = b"%%EOF";
        for i in (0..=(data.len().saturating_sub(marker.len()))).rev() {
            if &data[i..i + marker.len()] == marker {
                let mut end = i + marker.len();
                while end < data.len() && (data[end] == b'\r' || data[end] == b'\n' || data[end] == b' ') {
                    end += 1;
                }
                return Some(end);
            }
        }

        None
    }
}

pub struct RiffContainerParser;

impl RiffContainerParser {
    /// Parses RIFF file length (header length field at offset 4 + 8 bytes).
    pub fn calculate_length(data: &[u8]) -> Option<usize> {
        if data.len() < 12 || &data[0..4] != b"RIFF" {
            return None;
        }

        let payload_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let total_len = payload_len + 8;
        if total_len <= data.len() {
            Some(total_len)
        } else {
            None
        }
    }
}