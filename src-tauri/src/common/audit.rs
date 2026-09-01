use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditActor {
    User(String),
    SystemEngine,
    AutomatedPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub sequence_number: u64,
    pub timestamp: DateTime<Utc>,
    pub actor: AuditActor,
    pub operation: String,
    pub target_id: String,
    pub parameters_json: String,
    pub result_status: String,
    pub verification_summary: Option<String>,
    pub error_message: Option<String>,
    pub previous_event_hash: String,
    pub current_event_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationCertificate {
    pub certificate_id: String,
    pub issued_at: DateTime<Utc>,
    pub device_stable_id: String,
    pub device_serial: String,
    pub operation_performed: String,
    pub standard_applied: String,
    pub verification_levels_achieved: Vec<String>,
    pub audit_chain_root_hash: String,
    pub audit_chain_tip_hash: String,
    pub public_key_pem: String,
    pub signature_hex: String,
}
