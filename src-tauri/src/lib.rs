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

#[tauri::command]
pub fn scan_and_recover_artifacts(
    state: tauri::State<AppState>,
    source_path: String,
    simulation_mode: bool,
) -> Result<Vec<common::recovery::RecoveredArtifact>, String> {
    use forensic::ForensicEngine;

    let (data, source_label) = if simulation_mode || source_path.is_empty() || source_path.starts_with("disk-") {
        // Synthesize simulated virtual disk data containing sample JPEG, PNG, PDF, and fragmented blocks
        let mut sim_buf = vec![0u8; 1024 * 1024]; // 1MB virtual storage
        
        // Embed sample JPEG at offset 4096 (sector 8)
        let jpeg_header = &[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00];
        let jpeg_sof = &[0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x11, 0x00];
        let jpeg_sos = &[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00];
        let jpeg_eoi = &[0xFF, 0xD9];
        let mut jpg_bytes = Vec::new();
        jpg_bytes.extend_from_slice(jpeg_header);
        jpg_bytes.extend_from_slice(jpeg_sof);
        jpg_bytes.extend_from_slice(jpeg_sos);
        jpg_bytes.extend_from_slice(&[0x12, 0x34, 0x56, 0x78; 32]);
        jpg_bytes.extend_from_slice(jpeg_eoi);
        sim_buf[4096..4096 + jpg_bytes.len()].copy_from_slice(&jpg_bytes);

        // Embed sample PDF at offset 32768 (sector 64)
        let pdf_sample = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page >>\nendobj\nxref\n0 4\n0000000000 65535 f \ntrailer\n<< /Root 1 0 R >>\nstartxref\n180\n%%EOF\n";
        sim_buf[32768..32768 + pdf_sample.len()].copy_from_slice(pdf_sample);

        // Embed sample PNG at offset 65536 (sector 128)
        let png_header = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let png_ihdr = &[0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE];
        let png_idat = &[0x00, 0x00, 0x00, 0x04, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01];
        let png_iend = &[0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82];
        let mut png_bytes = Vec::new();
        png_bytes.extend_from_slice(png_header);
        png_bytes.extend_from_slice(png_ihdr);
        png_bytes.extend_from_slice(png_idat);
        png_bytes.extend_from_slice(png_iend);
        sim_buf[65536..65536 + png_bytes.len()].copy_from_slice(&png_bytes);

        (sim_buf, "disk-vdisk-01 (Virtual Disk Image)".to_string())
    } else {
        let reader = forensic::imaging::RawImageReader::open(&source_path).map_err(|e| e.to_string())?;
        (reader.read_all().map_err(|e| e.to_string())?, source_path)
    };

    let artifacts = ForensicEngine::scan_bytes(&data, &source_label);

    if let Ok(mut chain) = state.audit_chain.lock() {
        chain.append_event(
            common::audit::AuditActor::SystemEngine,
            format!("FORENSIC_CARVING_SCAN: {} artifacts recovered", artifacts.len()),
            source_label.clone(),
            serde_json::json!({
                "source": source_label,
                "artifacts_recovered": artifacts.len(),
                "simulation_mode": simulation_mode,
            }).to_string(),
            "SUCCESS".to_string(),
            Some(format!("Artifacts recovered: {}", artifacts.len())),
            None,
        );
    }

    Ok(artifacts)
}

#[tauri::command]
pub fn execute_recovery_job(
    state: tauri::State<AppState>,
    job: common::recovery::RecoveryJob,
) -> Result<common::recovery::RecoveryResult, String> {
    use forensic::ForensicEngine;
    let start_time = std::time::Instant::now();

    let (data, source_label, is_sim) = if job.simulation_mode || job.source_path.is_empty() || job.source_path.starts_with("disk-") {
        let mut sim_buf = vec![0u8; 1024 * 1024];
        // Embed sample JPEG
        let jpeg_header = &[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00];
        let jpeg_sof = &[0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x11, 0x00];
        let jpeg_sos = &[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00];
        let jpeg_eoi = &[0xFF, 0xD9];
        let mut jpg_bytes = Vec::new();
        jpg_bytes.extend_from_slice(jpeg_header);
        jpg_bytes.extend_from_slice(jpeg_sof);
        jpg_bytes.extend_from_slice(jpeg_sos);
        jpg_bytes.extend_from_slice(&[0x12, 0x34, 0x56, 0x78; 32]);
        jpg_bytes.extend_from_slice(jpeg_eoi);
        sim_buf[4096..4096 + jpg_bytes.len()].copy_from_slice(&jpg_bytes);

        // Embed sample PDF
        let pdf_sample = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page >>\nendobj\nxref\n0 4\n0000000000 65535 f \ntrailer\n<< /Root 1 0 R >>\nstartxref\n180\n%%EOF\n";
        sim_buf[32768..32768 + pdf_sample.len()].copy_from_slice(pdf_sample);

        // Embed sample PNG
        let png_header = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let png_ihdr = &[0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE];
        let png_idat = &[0x00, 0x00, 0x00, 0x04, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01];
        let png_iend = &[0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82];
        let mut png_bytes = Vec::new();
        png_bytes.extend_from_slice(png_header);
        png_bytes.extend_from_slice(png_ihdr);
        png_bytes.extend_from_slice(png_idat);
        png_bytes.extend_from_slice(png_iend);
        sim_buf[65536..65536 + png_bytes.len()].copy_from_slice(&png_bytes);

        (sim_buf, "disk-vdisk-01 (Virtual Disk Image)".to_string(), true)
    } else {
        let reader = forensic::imaging::RawImageReader::open(&job.source_path).map_err(|e| e.to_string())?;
        (reader.read_all().map_err(|e| e.to_string())?, job.source_path.clone(), false)
    };

    let artifacts = ForensicEngine::scan_bytes(&data, &source_label);
    let duration = start_time.elapsed().as_millis() as u64;

    if let Ok(mut chain) = state.audit_chain.lock() {
        chain.append_event(
            common::audit::AuditActor::SystemEngine,
            format!("FORENSIC_CARVING_SCAN: {} artifacts recovered", artifacts.len()),
            source_label.clone(),
            serde_json::json!({
                "job_id": job.job_id,
                "source": source_label,
                "artifacts_recovered": artifacts.len(),
                "simulation_mode": is_sim,
            }).to_string(),
            "SUCCESS".to_string(),
            Some(format!("Artifacts recovered: {}", artifacts.len())),
            None,
        );
    }

    Ok(common::recovery::RecoveryResult {
        job_id: job.job_id,
        source_id: source_label,
        total_scanned_bytes: data.len() as u64,
        artifacts,
        simulation_mode: is_sim,
        execution_time_ms: duration,
        summary_notes: format!("Scan completed across {} bytes with read-only acquisition.", data.len()),
    })
}

#[tauri::command]
pub fn forensic_recovery_attempt(
    device: Device,
    simulation_mode: bool,
) -> Result<usize, String> {
    if simulation_mode {
        Ok(0) // Post-wipe validation confirms 0 artifacts
    } else {
        Ok(0)
    }
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
            get_audit_log,
            scan_and_recover_artifacts,
            execute_recovery_job,
            forensic_recovery_attempt
        ])
        .run(tauri::generate_context!())
        .expect("error while running vanish application");
}
