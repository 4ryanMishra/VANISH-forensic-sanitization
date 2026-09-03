use serde::{Deserialize, Serialize};

/// The four verification levels defined in the VANISH verification matrix.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum VerificationLevel {
    /// L1: Logical filesystem layer — partition table and directory metadata inspection.
    L1Logical,
    /// L2: Host-visible block layer — LBA sampling, pattern checking, Shannon entropy.
    L2HostVisible,
    /// L3: Device-reported — NVMe Sanitize Status Log (SSTAT, SPROG, Global Data Erased bit).
    ///     For non-NVMe targets (e.g. USB flash) this is explicitly Unsupported.
    L3DeviceReported,
    /// L4: Forensic validation — Deep carving and bi-fragment artifact recovery.
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
pub enum VerificationStatus {
    /// Verification passed with verifiable evidence.
    Pass,
    /// Verification detected residual data or recovered artifacts.
    Fail,
    /// Verification cannot be performed on physical target safely without hardware/privilege access.
    NotAvailable,
    /// Verification level is architecturally inapplicable to this media class (e.g. L3 NVMe on USB flash).
    Unsupported,
    /// Inconclusive readings or indeterminate sampling density.
    Inconclusive,
}

// Backward-compatibility aliases
pub type LevelStatus = VerificationStatus;

/// Result from a single verification level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub level: VerificationLevel,
    pub status: VerificationStatus,
    pub method: String,
    pub evidence: Vec<String>,
    pub timestamp: String,
    pub limitations: Vec<String>,
    pub confidence_pct: u8,
    pub detail: String,
}

// Backward-compatibility alias
pub type LevelResult = VerificationResult;

/// Aggregated result from the full multi-level verification run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub target_id: String,
    pub levels_executed: Vec<VerificationLevel>,
    pub results: Vec<VerificationResult>,
    /// True only if every executed (non-Unsupported/non-NotAvailable) level passed.
    pub overall_passed: bool,
    pub confidence_pct: u8,
    pub timestamp_utc: String,
    /// Any levels not supported by this media type (reported transparently).
    pub unsupported_levels: Vec<VerificationLevel>,
    pub is_simulation: bool,
}

