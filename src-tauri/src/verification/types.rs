use serde::{Deserialize, Serialize};

/// The four verification levels defined in the VANISH verification matrix.
/// Each level provides a different depth of post-sanitization assurance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum VerificationLevel {
    /// L1: Logical filesystem layer — partition table and directory metadata inspection.
    L1Logical,
    /// L2: Host-visible block layer — LBA sampling, pattern checking, Shannon entropy.
    L2HostVisible,
    /// L3: Device-reported — NVMe Sanitize Status Log (SSTAT, SPROG, Global Data Erased bit).
    ///     For non-NVMe targets (e.g. USB flash) this is explicitly Unsupported.
    L3DeviceReported,
    /// L4: Forensic validation — integration handshake with Subodeep's recovery pipeline
    ///     to certify data is unrecoverable at file-carving depth.
    L4Forensic,
}

impl std::fmt::Display for VerificationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::L1Logical => write!(f, "L1_LOGICAL"),
            Self::L2HostVisible => write!(f, "L2_HOST_VISIBLE"),
            Self::L3DeviceReported => write!(f, "L3_DEVICE_REPORTED"),
            Self::L4Forensic => write!(f, "L4_FORENSIC"),
        }
    }
}

/// Outcome status for one verification level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LevelStatus {
    /// Verification passed with full confidence.
    Passed,
    /// Verification level is not applicable to this media type (e.g. L3 on USB flash).
    Unsupported,
    /// Verification detected a residual signal — sanitization may be incomplete.
    Failed,
    /// The verification pass could not be executed (e.g. device disconnected mid-check).
    Error,
}

/// Result from a single verification level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelResult {
    pub level: VerificationLevel,
    pub status: LevelStatus,
    pub confidence_pct: u8,
    pub detail: String,
    pub evidence: Vec<String>,
}

/// Aggregated result from the full multi-level verification run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub target_id: String,
    pub levels_executed: Vec<VerificationLevel>,
    pub results: Vec<LevelResult>,
    /// True only if every executed (non-Unsupported) level passed.
    pub overall_passed: bool,
    pub confidence_pct: u8,
    pub timestamp_utc: String,
    /// Any levels not supported by this media type (reported transparently).
    pub unsupported_levels: Vec<VerificationLevel>,
}
