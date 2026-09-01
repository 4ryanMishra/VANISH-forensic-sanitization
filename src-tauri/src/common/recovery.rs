use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ArtifactFormat {
    Jpeg,
    Pdf,
    Zip,
    Png,
    Sqlite,
    PlainText,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidationStatus {
    Valid,
    Corrupted,
    Truncated,
    Unverified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CarvingMethod {
    ContiguousSignature,
    FragmentedReconstruction,
    FilesystemMetadata,
    RawScan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactProvenance {
    pub source_id: String,
    pub detection_method: CarvingMethod,
    pub sector_ranges: Vec<(u64, u64)>,
    pub entropy_score: f64,
    pub header_magic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredArtifact {
    pub artifact_id: String,
    pub source_id: String,
    pub source_offsets: Vec<(u64, u64)>,
    pub format: ArtifactFormat,
    pub original_path: Option<String>,
    pub extracted_path: Option<String>,
    pub size_bytes: u64,
    pub sha256: String,
    pub validation_status: ValidationStatus,
    pub confidence_score: f32, // 0.0 to 1.0
    pub provenance: ArtifactProvenance,
}
