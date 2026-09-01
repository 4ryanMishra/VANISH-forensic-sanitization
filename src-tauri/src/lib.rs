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

use common::device::Device;
use common::sanitization::{SanitizationPlan, SanitizationStandard};
use common::audit::AuditEvent;
use device::DeviceDiscoveryService;
use policy::PolicyEngine;
use audit::hash_chain::AuditChain;
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
            get_audit_log
        ])
        .run(tauri::generate_context!())
        .expect("error while running vanish application");
}
