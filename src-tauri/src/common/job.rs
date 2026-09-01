use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum JobState {
    Created,
    Validating,
    Ready,
    Armed,
    Running,
    Verifying,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JobProgress {
    pub current_phase: String,
    pub bytes_processed: u64,
    pub total_bytes: u64,
    pub percentage: f32,
    pub eta_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub job_id: String,
    pub job_type: String,
    pub state: JobState,
    pub target_id: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub progress: Option<JobProgress>,
    pub error: Option<String>,
}
