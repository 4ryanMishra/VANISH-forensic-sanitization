use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ArtifactFormat {
    Jpeg,
    Pdf,
    Zip,
    Png,
    Sqlite,
    PlainText,
    Gif,
    Riff,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidationStatus {
    Valid,
    Corrupted,
    Truncated,
    Unverified,
    FalsePositive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CarvingMethod {
    ContiguousSignature,
    FragmentedReconstruction,
    FilesystemMetadata,
    RawScan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceSourceType {
    SimulationBuffer,
    ForensicImageFile(String),
    PhysicalReadOnlyDevice(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentRecord {
    pub sequence_index: usize,
    pub start_offset: u64,
    pub length_bytes: usize,
    pub sector_start: u64,
    pub sector_end: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactProvenance {
    pub source_id: String,
    pub source_type_desc: String,
    pub detection_method: CarvingMethod,
    pub validation_method: String,
    pub sector_ranges: Vec<(u64, u64)>,
    pub fragments: Vec<FragmentRecord>,
    pub entropy_score: f64,
    pub header_magic: String,
    pub recovery_timestamp_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredArtifact {
    pub artifact_id: String,
    pub source_id: String,
    pub source_hash: Option<String>,
    pub source_offsets: Vec<(u64, u64)>,
    pub format: ArtifactFormat,
    pub original_path: Option<String>,
    pub extracted_path: Option<String>,
    pub size_bytes: u64,
    pub sha256: String, // Canonical forensic evidence hash
    pub optional_blake3: Option<String>, // High-throughput internal processing hash
    pub validation_status: ValidationStatus,
    pub validation_method: String,
    pub confidence_score: f32, // 0.0 to 1.0 based on structural evidence
    pub timestamp_utc: String,
    pub provenance: ArtifactProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryJob {
    pub job_id: String,
    pub source_path: String,
    pub scan_mode: String,
    pub simulation_mode: bool,
    pub created_at_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryResult {
    pub job_id: String,
    pub source_id: String,
    pub total_scanned_bytes: u64,
    pub artifacts: Vec<RecoveredArtifact>,
    pub simulation_mode: bool,
    pub execution_time_ms: u64,
    pub summary_notes: String,
}

