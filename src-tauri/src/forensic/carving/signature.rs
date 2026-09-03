use crate::common::recovery::ArtifactFormat;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerType {
    JpegStream,
    PngChunks,
    PdfStream,
    ZipArchive,
    SqliteDatabase,
    Mp4IsoBmff,
    GifStream,
    RiffContainer,
    Generic,
}

pub struct MagicSignature {
    pub format: ArtifactFormat,
    pub container_type: ContainerType,
    pub header: &'static [u8],
    pub footer: Option<&'static [u8]>,
    pub max_size_bytes: u64,
    pub min_size_bytes: u64,
    pub default_extension: &'static str,
}

pub static KNOWN_SIGNATURES: &[MagicSignature] = &[
    // JPEG: SOI = FF D8 FF, EOI = FF D9
    MagicSignature {
        format: ArtifactFormat::Jpeg,
        container_type: ContainerType::JpegStream,
        header: &[0xFF, 0xD8, 0xFF],
        footer: Some(&[0xFF, 0xD9]),
        max_size_bytes: 50 * 1024 * 1024, // 50MB
        min_size_bytes: 64,
        default_extension: "jpg",
    },
    // PNG: 89 50 4E 47 0D 0A 1A 0A, IEND = 49 45 4E 44 AE 42 60 82
    MagicSignature {
        format: ArtifactFormat::Png,
        container_type: ContainerType::PngChunks,
        header: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        footer: Some(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
        max_size_bytes: 50 * 1024 * 1024,
        min_size_bytes: 67, // Minimum valid PNG size with IHDR + IDAT + IEND
        default_extension: "png",
    },
    // PDF: %PDF- (25 50 44 46 2D), EOF marker = %%EOF (25 25 45 4F 46)
    MagicSignature {
        format: ArtifactFormat::Pdf,
        container_type: ContainerType::PdfStream,
        header: &[0x25, 0x50, 0x44, 0x46, 0x2D],
        footer: Some(&[0x25, 0x25, 0x45, 0x4F, 0x46]),
        max_size_bytes: 150 * 1024 * 1024, // 150MB
        min_size_bytes: 32,
        default_extension: "pdf",
    },
    // ZIP / Office Open XML (DOCX, XLSX, PPTX, APK, JAR): PK\x03\x04
    MagicSignature {
        format: ArtifactFormat::Zip,
        container_type: ContainerType::ZipArchive,
        header: &[0x50, 0x4B, 0x03, 0x04],
        footer: Some(&[0x50, 0x4B, 0x05, 0x06]), // EOCD record
        max_size_bytes: 500 * 1024 * 1024,
        min_size_bytes: 22, // Empty zip archive is 22 bytes EOCD
        default_extension: "zip",
    },
    // SQLite 3: SQLite format 3\0 (53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00)
    MagicSignature {
        format: ArtifactFormat::Sqlite,
        container_type: ContainerType::SqliteDatabase,
        header: &[0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00],
        footer: None,
        max_size_bytes: 500 * 1024 * 1024,
        min_size_bytes: 512,
        default_extension: "sqlite",
    },
    // GIF87a / GIF89a: 47 49 46 38, Trailer = 3B
    MagicSignature {
        format: ArtifactFormat::Gif,
        container_type: ContainerType::GifStream,
        header: &[0x47, 0x49, 0x46, 0x38],
        footer: Some(&[0x3B]),
        max_size_bytes: 50 * 1024 * 1024,
        min_size_bytes: 14,
        default_extension: "gif",
    },
    // RIFF (WAV, AVI, WEBP): 52 49 46 46
    MagicSignature {
        format: ArtifactFormat::Riff,
        container_type: ContainerType::RiffContainer,
        header: &[0x52, 0x49, 0x46, 0x46],
        footer: None,
        max_size_bytes: 500 * 1024 * 1024,
        min_size_bytes: 12,
        default_extension: "riff",
    },
];

pub fn get_signature_for_format(format: &ArtifactFormat) -> Option<&'static MagicSignature> {
    KNOWN_SIGNATURES.iter().find(|s| &s.format == format)
}
