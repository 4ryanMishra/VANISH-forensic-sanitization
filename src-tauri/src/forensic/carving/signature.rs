use crate::common::recovery::ArtifactFormat;

pub struct MagicSignature {
    pub format: ArtifactFormat,
    pub header: &'static [u8],
    pub footer: Option<&'static [u8]>,
    pub max_size_bytes: u64,
}

pub static KNOWN_SIGNATURES: &[MagicSignature] = &[
    // JPEG: SOI = FF D8 FF, EOI = FF D9
    MagicSignature {
        format: ArtifactFormat::Jpeg,
        header: &[0xFF, 0xD8, 0xFF],
        footer: Some(&[0xFF, 0xD9]),
        max_size_bytes: 50 * 1024 * 1024, // 50MB
    },
    // PDF: %PDF- (25 50 44 46 2D), EOF marker = %%EOF
    MagicSignature {
        format: ArtifactFormat::Pdf,
        header: &[0x25, 0x50, 0x44, 0x46, 0x2D],
        footer: Some(&[0x25, 0x25, 0x45, 0x4F, 0x46]),
        max_size_bytes: 100 * 1024 * 1024, // 100MB
    },
    // PNG: 89 50 4E 47 0D 0A 1A 0A, IEND = 49 45 4E 44 AE 42 60 82
    MagicSignature {
        format: ArtifactFormat::Png,
        header: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        footer: Some(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
        max_size_bytes: 50 * 1024 * 1024,
    },
    // ZIP / Office XML: 50 4B 03 04
    MagicSignature {
        format: ArtifactFormat::Zip,
        header: &[0x50, 0x4B, 0x03, 0x04],
        footer: Some(&[0x50, 0x4B, 0x05, 0x06]), // End of central directory record
        max_size_bytes: 500 * 1024 * 1024,
    },
];

pub struct SignatureScanner;

impl SignatureScanner {
    pub fn find_candidates(data: &[u8]) -> Vec<(usize, &'static MagicSignature)> {
        let mut matches = Vec::new();

        for sig in KNOWN_SIGNATURES {
            let hlen = sig.header.len();
            if data.len() < hlen {
                continue;
            }

            for i in 0..=(data.len() - hlen) {
                if &data[i..i + hlen] == sig.header {
                    matches.push((i, sig));
                }
            }
        }

        matches
    }
}
