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
use device::DeviceDiscoveryService;
use policy::PolicyEngine;
use sanitization::{ExecutionSummary, SanitizationAdapter};
use std::sync::Mutex;

pub struct AppState {
    pub audit_chain: Mutex<AuditChain>,
    pub discovery: DeviceDiscoveryService,
    pub policy: PolicyEngine,
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

    // Record execution event in audit chain
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
pub fn get_audit_log(state: tauri::State<AppState>) -> Result<Vec<AuditEvent>, String> {
    let chain = state.audit_chain.lock().map_err(|e| e.to_string())?;
    Ok(chain.get_events().to_vec())
}

pub fn run() {
    let state = AppState {
        audit_chain: Mutex::new(AuditChain::new()),
        discovery: DeviceDiscoveryService::new(),
        policy: PolicyEngine::new(),
    };

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            list_devices,
            get_recommended_plan,
            execute_sanitization_plan,
            get_audit_log
        ])
        .run(tauri::generate_context!())
        .expect("error while running vanish application");
}
