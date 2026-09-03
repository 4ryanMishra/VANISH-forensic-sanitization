use crate::common::audit::{AuditActor, AuditEvent};
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone)]
pub struct AuditChain {
    pub events: Vec<AuditEvent>,
    pub last_hash: String,
}

impl AuditChain {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            last_hash: GENESIS_HASH.to_string(),
        }
    }

    pub fn append_event(
        &mut self,
        actor: AuditActor,
        operation: String,
        target_id: String,
        parameters_json: String,
        result_status: String,
        verification_summary: Option<String>,
        error_message: Option<String>,
    ) -> AuditEvent {
        let sequence_number = self.events.len() as u64 + 1;
        let timestamp = Utc::now();
        let event_id = format!("evt-{}", Uuid::new_v4());

        let current_event_hash = Self::compute_canonical_event_hash(
            sequence_number,
            &event_id,
            &timestamp.to_rfc3339(),
            &actor,
            &operation,
            &target_id,
            &parameters_json,
            &result_status,
            verification_summary.as_deref(),
            error_message.as_deref(),
            &self.last_hash,
        );

        let event = AuditEvent {
            event_id,
            sequence_number,
            timestamp,
            actor,
            operation,
            target_id,
            parameters_json,
            result_status,
            verification_summary,
            error_message,
            previous_event_hash: self.last_hash.clone(),
            current_event_hash: current_event_hash.clone(),
        };

        self.last_hash = current_event_hash;
        self.events.push(event.clone());
        event
    }

    /// Computes the canonical SHA-256 hash across all serialized event fields
    pub fn compute_canonical_event_hash(
        sequence_number: u64,
        event_id: &str,
        timestamp_iso: &str,
        actor: &AuditActor,
        operation: &str,
        target_id: &str,
        parameters_json: &str,
        result_status: &str,
        verification_summary: Option<&str>,
        error_message: Option<&str>,
        previous_event_hash: &str,
    ) -> String {
        let canonical_str = format!(
            "{}:{}:{}:{:?}:{}:{}:{}:{}:{}:{}:{}",
            sequence_number,
            event_id,
            timestamp_iso,
            actor,
            operation,
            target_id,
            parameters_json,
            result_status,
            verification_summary.unwrap_or(""),
            error_message.unwrap_or(""),
            previous_event_hash
        );

        let mut hasher = Sha256::new();
        hasher.update(canonical_str.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verifies the entire chained sequence from genesis
    pub fn verify_integrity(&self) -> bool {
        Self::verify_events(&self.events)
    }

    /// Verifies any slice of AuditEvents against hash link and content validity
    pub fn verify_events(events: &[AuditEvent]) -> bool {
        let mut prev_hash = GENESIS_HASH.to_string();
        for event in events {
            if event.previous_event_hash != prev_hash {
                return false;
            }

            let computed_hash = Self::compute_canonical_event_hash(
                event.sequence_number,
                &event.event_id,
                &event.timestamp.to_rfc3339(),
                &event.actor,
                &event.operation,
                &event.target_id,
                &event.parameters_json,
                &event.result_status,
                event.verification_summary.as_deref(),
                event.error_message.as_deref(),
                &event.previous_event_hash,
            );

            if event.current_event_hash != computed_hash {
                return false;
            }

            prev_hash = event.current_event_hash.clone();
        }
        true
    }

    pub fn get_events(&self) -> &[AuditEvent] {
        &self.events
    }

    pub fn get_tip_hash(&self) -> &str {
        &self.last_hash
    }
}
