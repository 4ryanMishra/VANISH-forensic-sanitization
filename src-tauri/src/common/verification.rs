use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LevelStatus {
    Verified,
    PartiallyVerified,
    NotVerified,
    Failed,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelVerificationDetail {
    pub status: LevelStatus,
    pub description: String,
    pub sectors_checked: Option<u64>,
    pub matching_expected_pattern_pct: Option<f32>,
    pub mean_entropy: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub verification_id: String,
    pub target_id: String,
    pub l1_logical: LevelVerificationDetail,
    pub l2_host_visible: LevelVerificationDetail,
    pub l3_device_reported: LevelVerificationDetail,
    pub l4_forensic_validation: LevelVerificationDetail,
    pub scope_description: String,
    pub warnings: Vec<String>,
    pub summary_statement: String,
}
