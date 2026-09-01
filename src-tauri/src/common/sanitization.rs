use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SanitizationStandard {
    Nist80088Clear,
    Nist80088Purge,
    Dod522022M3Pass,
    Ieee2883Purge,
    SinglePassZero,
    SinglePassRandom,
    CustomPattern,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SanitizationMethod {
    NvmeSanitizeBlockErase,
    NvmeSanitizeCryptoErase,
    NvmeSanitizeOverwrite,
    AtaSecureErase,
    AtaEnhancedSecureErase,
    HostSequentialOverwrite { passes: u32, pattern_desc: String },
    FileTargetedShredding { passes: u32, zero_slack: bool },
    SimulatedSanitization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationPlan {
    pub plan_id: String,
    pub target_id: String,
    pub standard: SanitizationStandard,
    pub method: SanitizationMethod,
    pub rationale: String,
    pub prerequisites: Vec<String>,
    pub warnings: Vec<String>,
    pub estimated_duration_seconds: Option<u64>,
    pub verification_levels_planned: Vec<String>,
    pub simulation_mode: bool,
}
