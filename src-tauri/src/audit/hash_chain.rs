use crate::common::audit::{AuditActor, AuditEvent};
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub struct AuditChain {
    events: Vec<AuditEvent>,
    last_hash: String,
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

        // Canonical string for hashing
        let canonical_str = format!(
            "{}:{}:{}:{:?}:{}:{}:{}:{}:{}:{}",
            sequence_number,
            event_id,
            timestamp.to_rfc3339(),
            actor,
            operation,
            target_id,
            parameters_json,
            result_status,
            self.last_hash,
            error_message.as_deref().unwrap_or("")
        );

        let mut hasher = Sha256::new();
        hasher.update(canonical_str.as_bytes());
        let current_event_hash = hex::encode(hasher.finalize());

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

    pub fn verify_integrity(&self) -> bool {
        let mut prev_hash = GENESIS_HASH.to_string();
        for event in &self.events {
            if event.previous_event_hash != prev_hash {
                return false;
            }

            let canonical_str = format!(
                "{}:{}:{}:{:?}:{}:{}:{}:{}:{}:{}",
                event.sequence_number,
                event.event_id,
                event.timestamp.to_rfc3339(),
                event.actor,
                event.operation,
                event.target_id,
                event.parameters_json,
                event.result_status,
                event.previous_event_hash,
                event.error_message.as_deref().unwrap_or("")
            );

            let mut hasher = Sha256::new();
            hasher.update(canonical_str.as_bytes());
            let computed_hash = hex::encode(hasher.finalize());

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
