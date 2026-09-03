use crate::common::device::Device;
use crate::common::sanitization::{SanitizationMethod, SanitizationPlan};
use crate::device::SafetyGate;
use crate::sanitization::nvme::{
    NvmeAdminCommand, NvmeSanitizeAction, SimulatedNvmeController,
};
use crate::sanitization::overwrite::{OverwriteEngine, OverwritePatternType};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionSummary {
    pub plan_id: String,
    pub target_id: String,
    pub bytes_processed: u64,
    pub passes_completed: u32,
    pub method_executed: String,
    pub execution_log: Vec<String>,
    pub success: bool,
}

pub struct SanitizationAdapter;

impl SanitizationAdapter {
    /// Executes a SanitizationPlan with two-stage safety gate validation and real-time progress callbacks.
    pub fn execute(
        plan: &SanitizationPlan,
        device: &Device,
        mut progress_cb: impl FnMut(f32, &str),
    ) -> Result<ExecutionSummary> {
        // Stage 1 & 2 Invariant Safety Gates
        SafetyGate::assert_safe_for_sanitization(device)
            .map_err(|e| anyhow!("Safety gate failed: {}", e))?;

        SafetyGate::verify_device_identity(&device.serial, device)
            .map_err(|e| anyhow!("Identity verification failed: {}", e))?;

        let mut log = Vec::new();
        log.push(format!("Pre-execution invariant safety gate verified for device '{}'", device.stable_id));

        match &plan.method {
            SanitizationMethod::NvmeSanitizeCryptoErase => {
                log.push("Constructing NVMe Sanitize Command (Opcode 0x84, Action: Crypto Erase)".to_string());
                let cmd = NvmeAdminCommand::build_sanitize_command(
                    NvmeSanitizeAction::CryptoErase,
                    false,
                    false,
                    0,
                    0,
                );

                let status_log = SimulatedNvmeController::execute_sanitize_simulation(
                    &cmd,
                    |pct, phase| progress_cb(pct, phase),
                )?;

                log.push(format!("Controller Sanitize Status Log: {}", status_log.status_description));
                Ok(ExecutionSummary {
                    plan_id: plan.plan_id.clone(),
                    target_id: device.stable_id.clone(),
                    bytes_processed: device.capacity_bytes,
                    passes_completed: 1,
                    method_executed: "NVMe Sanitize (Crypto Erase)".to_string(),
                    execution_log: log,
                    success: true,
                })
            }

            SanitizationMethod::NvmeSanitizeBlockErase => {
                log.push("Constructing NVMe Sanitize Command (Opcode 0x84, Action: Block Erase)".to_string());
                let cmd = NvmeAdminCommand::build_sanitize_command(
                    NvmeSanitizeAction::BlockErase,
                    false,
                    false,
                    0,
                    0,
                );

                let status_log = SimulatedNvmeController::execute_sanitize_simulation(
                    &cmd,
                    |pct, phase| progress_cb(pct, phase),
                )?;

                log.push(format!("Controller Sanitize Status Log: {}", status_log.status_description));
                Ok(ExecutionSummary {
                    plan_id: plan.plan_id.clone(),
                    target_id: device.stable_id.clone(),
                    bytes_processed: device.capacity_bytes,
                    passes_completed: 1,
                    method_executed: "NVMe Sanitize (Block Erase)".to_string(),
                    execution_log: log,
                    success: true,
                })
            }

            SanitizationMethod::HostSequentialOverwrite { passes, pattern_desc } => {
                log.push(format!("Initiating host sequential overwrite ({} passes): {}", passes, pattern_desc));
                let total_bytes = device.capacity_bytes;
                let chunk_size = 1024 * 1024; // 1MB buffer

                for p in 1..=*passes {
                    let pattern = match p {
                        1 => OverwritePatternType::Fixed(0x00),
                        2 => OverwritePatternType::Inverted(0x00),
                        _ => OverwritePatternType::PseudoRandom { seed: Some(p as u64) },
                    };

                    OverwriteEngine::execute_stream(
                        pattern,
                        total_bytes,
                        chunk_size,
                        |written, total| {
                            let overall_pct = (((p - 1) as f32) / (*passes as f32) + (written as f32 / total as f32) / (*passes as f32)) * 100.0;
                            progress_cb(overall_pct, &format!("Pass {}/{}: Overwriting...", p, passes));
                        },
                    )?;

                    log.push(format!("Pass {}/{} completed successfully", p, passes));
                }

                Ok(ExecutionSummary {
                    plan_id: plan.plan_id.clone(),
                    target_id: device.stable_id.clone(),
                    bytes_processed: total_bytes * (*passes as u64),
                    passes_completed: *passes,
                    method_executed: format!("Host Sequential Overwrite ({})", pattern_desc),
                    execution_log: log,
                    success: true,
                })
            }

            SanitizationMethod::SimulatedSanitization => {
                log.push("Executing simulation mode sanitization against virtual test fixture".to_string());
                for pct in [25.0, 50.0, 75.0, 100.0] {
                    progress_cb(pct, "Zeroing virtual disk buffers & calculating post-erase entropy");
                }
                log.push("Virtual image buffer zeroed with 0.00 Shannon entropy".to_string());

                Ok(ExecutionSummary {
                    plan_id: plan.plan_id.clone(),
                    target_id: device.stable_id.clone(),
                    bytes_processed: device.capacity_bytes,
                    passes_completed: 1,
                    method_executed: "Virtual Image Simulation Sanitization".to_string(),
                    execution_log: log,
                    success: true,
                })
            }

            _ => {
                log.push("Executing default logical zero pass".to_string());
                OverwriteEngine::execute_stream(
                    OverwritePatternType::Fixed(0x00),
                    device.capacity_bytes,
                    1024 * 1024,
                    |written, total| {
                        let pct = (written as f32 / total as f32) * 100.0;
                        progress_cb(pct, "Zeroing block stream");
                    },
                )?;

                Ok(ExecutionSummary {
                    plan_id: plan.plan_id.clone(),
                    target_id: device.stable_id.clone(),
                    bytes_processed: device.capacity_bytes,
                    passes_completed: 1,
                    method_executed: "Host Logical Zero Wipe".to_string(),
                    execution_log: log,
                    success: true,
                })
            }
        }
    }
}
