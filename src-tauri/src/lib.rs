pub mod audit;
pub mod common;
pub mod deletion;
pub mod device;
pub mod forensic;
pub mod platform;
pub mod policy;
pub mod reporting;
pub mod sanitization;
pub mod verification;

use common::audit::AuditEvent;
use common::device::Device;
use common::sanitization::{SanitizationPlan, SanitizationStandard};
use audit::hash_chain::AuditChain;
use audit::{CertificateIssuer, OperationSummary, SanitizationCertificate, SigningKeypair};
use device::DeviceDiscoveryService;
use policy::PolicyEngine;
use sanitization::{ExecutionSummary, SanitizationAdapter};
use std::sync::Mutex;

pub struct AppState {
    pub audit_chain: Mutex<AuditChain>,
    pub discovery: DeviceDiscoveryService,
    pub policy: PolicyEngine,
    /// Session signing keypair — generated fresh per process start.
    /// Discarded on exit; proves this run's events are internally consistent.
    pub session_keypair: SigningKeypair,
}

#[tauri::command]
pub fn list_devices(state: tauri::State<AppState>) -> Result<Vec<Device>, String> {
    state.discovery.list_devices().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_recommended_plan(
    state: tauri::State<AppState>,
    device: Device,
    standard: SanitizationStandard,
) -> Result<SanitizationPlan, String> {
    Ok(state.policy.recommend_plan(&device, standard))
}

#[tauri::command]
pub fn execute_sanitization_plan(
    state: tauri::State<AppState>,
    plan: SanitizationPlan,
    device: Device,
) -> Result<ExecutionSummary, String> {
    let summary = SanitizationAdapter::execute(&plan, &device, |_pct, _phase| {})
        .map_err(|e| e.to_string())?;

    if let Ok(mut chain) = state.audit_chain.lock() {
        chain.append_event(
            common::audit::AuditActor::SystemEngine,
            format!("SANITIZATION_EXECUTION: {}", summary.method_executed),
            device.stable_id.clone(),
            serde_json::to_string(&plan).unwrap_or_default(),
            if summary.success { "SUCCESS".to_string() } else { "FAILED".to_string() },
            Some(format!("Passes completed: {}", summary.passes_completed)),
            None,
        );
    }

    Ok(summary)
}

#[tauri::command]
pub fn run_verification(
    state: tauri::State<AppState>,
    device: Device,
    sanitization_method: String,
    simulation_mode: bool,
) -> Result<verification::VerificationReport, String> {
    use verification::{VerificationEngine, VerificationLevel, VerificationRequest};

    let req = VerificationRequest {
        device: device.clone(),
        levels_requested: vec![
            VerificationLevel::L1Logical,
            VerificationLevel::L2HostVisible,
            VerificationLevel::L3DeviceReported,
            VerificationLevel::L4Forensic,
        ],
        sanitization_method,
        simulation_mode,
    };

    let engine = VerificationEngine::new();
    let report = engine.run(&req);

    if let Ok(mut chain) = state.audit_chain.lock() {
        chain.append_event(
            common::audit::AuditActor::SystemEngine,
            "VERIFICATION_RUN: L1-L4 matrix".to_string(),
            device.stable_id.clone(),
            serde_json::to_string(&report).unwrap_or_default(),
            if report.overall_passed { "SUCCESS".to_string() } else { "FAILED".to_string() },
            Some(format!("Confidence: {}%", report.confidence_pct)),
            None,
        );
    }

    Ok(report)
}

#[tauri::command]
pub fn issue_certificate(
    state: tauri::State<AppState>,
    device: Device,
    sanitization_method: String,
    passes_completed: u32,
    bytes_processed: u64,
    simulation_mode: bool,
    standard: String,
) -> Result<SanitizationCertificate, String> {
    use verification::{VerificationEngine, VerificationLevel, VerificationRequest};

    // Run a fresh L1–L4 verification to embed in the certificate
    let ver_req = VerificationRequest {
        device: device.clone(),
        levels_requested: vec![
            VerificationLevel::L1Logical,
            VerificationLevel::L2HostVisible,
            VerificationLevel::L3DeviceReported,
            VerificationLevel::L4Forensic,
        ],
        sanitization_method: sanitization_method.clone(),
        simulation_mode,
    };
    let verification_report = VerificationEngine::new().run(&ver_req);

    let op_summary = OperationSummary {
        standard,
        method: sanitization_method.clone(),
        passes_completed,
        bytes_processed,
        simulation_mode,
    };

    let events_snapshot: Vec<AuditEvent> = {
        let chain = state.audit_chain.lock().map_err(|e| e.to_string())?;
        chain.get_events().to_vec()
    };

    let cert = CertificateIssuer::issue(
        &state.session_keypair,
        &device,
        op_summary,
        verification_report,
        &events_snapshot,
    )?;

    // Append certificate issuance to audit chain
    if let Ok(mut chain) = state.audit_chain.lock() {
        chain.append_event(
            common::audit::AuditActor::SystemEngine,
            format!("CERTIFICATE_ISSUED: {}", cert.cert_id),
            device.stable_id.clone(),
            serde_json::json!({
                "cert_id": cert.cert_id,
                "key_id": cert.signing_identity.key_id,
                "audit_chain_root_hash": cert.audit_chain_root_hash,
                "confidence_pct": cert.verification_result.confidence_pct,
            }).to_string(),
            "SUCCESS".to_string(),
            Some(format!("Signature: {}...", &cert.signature[..16])),
            None,
        );
    }

    Ok(cert)
}

#[tauri::command]
pub fn verify_certificate(cert: SanitizationCertificate) -> Result<bool, String> {
    CertificateIssuer::verify(&cert)
}

#[tauri::command]
pub fn get_audit_log(state: tauri::State<AppState>) -> Result<Vec<AuditEvent>, String> {
    let chain = state.audit_chain.lock().map_err(|e| e.to_string())?;
    Ok(chain.get_events().to_vec())
}

pub fn run() {
    let state = AppState {
        audit_chain: Mutex::new(AuditChain::new()),
        discovery: DeviceDiscoveryService::new(),
        policy: PolicyEngine::new(),
        session_keypair: SigningKeypair::generate_session(),
    };

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            list_devices,
            get_recommended_plan,
            execute_sanitization_plan,
            run_verification,
            issue_certificate,
            verify_certificate,
            get_audit_log
        ])
        .run(tauri::generate_context!())
        .expect("error while running vanish application");
}
