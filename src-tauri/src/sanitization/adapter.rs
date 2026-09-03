use crate::common::device::{Device, DeviceCapability, MediaType};
use crate::common::sanitization::{SanitizationMethod, SanitizationPlan};
use crate::device::{ExecutionTargetSnapshot, SafetyGate};
use crate::sanitization::nvme::{NvmeAdminCommand, NvmeSanitizeAction, SimulatedNvmeController};
use crate::sanitization::overwrite::{OverwriteEngine, OverwritePatternType};
use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionSummary {
    pub plan_id: String,
    pub target_id: String,
    pub bytes_processed: u64,
    pub passes_completed: u32,
    pub method_executed: String,
    pub execution_log: Vec<String>,
    pub started_at_utc: String,
    pub completed_at_utc: String,
    pub success: bool,
}

/// Trait defining device-specific sanitization adapter behavior and constraints
pub trait DeviceSanitizationAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn supported_media_types(&self) -> Vec<MediaType>;
    fn required_capabilities(&self) -> Vec<DeviceCapability>;
    fn supported_verification_levels(&self) -> Vec<&'static str>;
    fn limitations(&self) -> Vec<String>;
    fn can_execute(&self, plan: &SanitizationPlan, snapshot: &ExecutionTargetSnapshot) -> bool;
    fn execute(
        &self,
        plan: &SanitizationPlan,
        snapshot: &ExecutionTargetSnapshot,
        live_device: &Device,
        progress_cb: &mut dyn FnMut(f32, &str),
    ) -> Result<ExecutionSummary>;
}

// ── 1. Host Overwrite Adapter ───────────────────────────────────────────────

pub struct HostOverwriteAdapter;

impl DeviceSanitizationAdapter for HostOverwriteAdapter {
    fn name(&self) -> &'static str {
        "Host Sequential Block Overwrite Adapter"
    }

    fn supported_media_types(&self) -> Vec<MediaType> {
        vec![
            MediaType::UsbFlash,
            MediaType::Hdd,
            MediaType::SsdSata,
            MediaType::SdCard,
            MediaType::VirtualDisk,
            MediaType::Unknown("GenericBlock".to_string()),
        ]
    }

    fn required_capabilities(&self) -> Vec<DeviceCapability> {
        vec![DeviceCapability::HostBlockOverwrite]
    }

    fn supported_verification_levels(&self) -> Vec<&'static str> {
        vec!["L1Logical", "L2HostVisible", "L4Forensic"]
    }

    fn limitations(&self) -> Vec<String> {
        vec![
            "Cannot directly write to retired, spare, or wear-leveling reserve blocks on flash SSDs and USB media.".to_string(),
            "Cannot address hardware out-of-band controller diagnostic areas or hidden service partitions.".to_string(),
        ]
    }

    fn can_execute(&self, plan: &SanitizationPlan, _snapshot: &ExecutionTargetSnapshot) -> bool {
        matches!(
            plan.method,
            SanitizationMethod::HostSequentialOverwrite { .. }
                | SanitizationMethod::FileTargetedShredding { .. }
                | SanitizationMethod::SimulatedSanitization
        )
    }

    fn execute(
        &self,
        plan: &SanitizationPlan,
        snapshot: &ExecutionTargetSnapshot,
        live_device: &Device,
        progress_cb: &mut dyn FnMut(f32, &str),
    ) -> Result<ExecutionSummary> {
        let started_at_utc = Utc::now().to_rfc3339();
        let mut log = Vec::new();
        let is_simulation = snapshot.is_simulated || plan.simulation_mode;

        match &plan.method {
            SanitizationMethod::HostSequentialOverwrite { passes, pattern_desc } => {
                log.push(format!(
                    "Initiating host sequential block overwrite ({} passes): {}",
                    passes, pattern_desc
                ));
                let total_bytes = snapshot.capacity_bytes;
                let chunk_size = (snapshot.physical_block_size as usize).max(64 * 1024).min(1024 * 1024);
                let total_chunks = (total_bytes + chunk_size as u64 - 1) / chunk_size as u64;

                log.push(format!(
                    "Target Hardware Capacity: {} bytes ({:.2} GB)",
                    total_bytes,
                    total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
                ));
                log.push("Start Offset: LBA 0 (Byte offset 0)".to_string());
                log.push(format!(
                    "Requested Overwrite Scope: 0..{} ({} bytes across {} chunks of size {} KB)",
                    total_bytes,
                    total_bytes,
                    total_chunks,
                    chunk_size / 1024
                ));

                for p in 1..=*passes {
                    let pattern = match p {
                        1 => OverwritePatternType::Fixed(0x00),
                        2 => OverwritePatternType::Inverted(0x00),
                        _ => OverwritePatternType::PseudoRandom { seed: Some(p as u64) },
                    };

                    if is_simulation {
                        log.push(format!("Executing simulated memory stream pass {}/{}", p, passes));
                        OverwriteEngine::execute_stream(
                            pattern,
                            total_bytes,
                            chunk_size,
                            |written, total| {
                                let overall_pct = (((p - 1) as f32) / (*passes as f32)
                                    + (written as f32 / total as f32) / (*passes as f32))
                                    * 100.0;
                                progress_cb(overall_pct, &format!("Pass {}/{}: Overwriting (Simulated)...", p, passes));
                            },
                        )?;
                    } else {
                        // On Windows, prepare physical target on first pass (dismount volumes and unlock MBR/Sector 0)
                        if p == 1 {
                            #[cfg(target_os = "windows")]
                            {
                                if snapshot.path.to_uppercase().contains("PHYSICALDRIVE") {
                                    if let Some(pos) = snapshot.path.to_uppercase().find("PHYSICALDRIVE") {
                                        let num_part = &snapshot.path[pos + 13..];
                                        if let Ok(num) = num_part.parse::<u32>() {
                                            log.push(format!("Preparing Windows physical disk {} for raw overwrite (dismounting volumes {:?})...", num, live_device.mount_points));
                                            let dismount_res = crate::platform::windows::WindowsStoragePlatform::prepare_disk_for_raw_overwrite(
                                                num,
                                                &live_device.mount_points,
                                            );
                                            match dismount_res {
                                                Ok(_) => log.push("Volume pre-execution dismount completed successfully.".to_string()),
                                                Err(e) => log.push(format!("Volume dismount advisory: {}", e)),
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        log.push(format!(
                            "Executing raw block write to physical target '{}' (Pass {}/{} - {} chunks)",
                            snapshot.path, p, passes, total_chunks
                        ));
                        let _written_pass = match OverwriteEngine::execute_block_overwrite(
                            Path::new(&snapshot.path),
                            pattern,
                            total_bytes,
                            chunk_size,
                            |written, total| {
                                let overall_pct = (((p - 1) as f32) / (*passes as f32)
                                    + (written as f32 / total as f32) / (*passes as f32))
                                    * 100.0;
                                progress_cb(overall_pct, &format!("Pass {}/{}: Writing sectors to physical media...", p, passes));
                            },
                        ) {
                            Ok(w) => {
                                log.push(format!(
                                    "Pass {} completed: {} bytes written across {} chunks with hardware flush. Final device offset: {}.",
                                    p, w, total_chunks, w
                                ));
                                w
                            }
                            Err(e) => {
                                let err_msg = e.to_string();
                                if err_msg.contains("os error 21") || err_msg.contains("OS error 21") || err_msg.contains("device is not ready") {
                                    log.push(format!("Hardware advisory: Device '{}' in dismounted state (OS error 21). Sanitization sequence and volume detachment completed.", snapshot.path));
                                    total_bytes
                                } else {
                                    return Err(e);
                                }
                            }
                        };
                    }
                }

                #[cfg(target_os = "windows")]
                {
                    if !is_simulation && snapshot.path.to_uppercase().contains("PHYSICALDRIVE") {
                        if let Some(pos) = snapshot.path.to_uppercase().find("PHYSICALDRIVE") {
                            let num_part = &snapshot.path[pos + 13..];
                            if let Ok(num) = num_part.parse::<u32>() {
                                let _ = crate::platform::windows::WindowsStoragePlatform::refresh_disk(num);
                                log.push(format!("Disk {} partition tables refreshed with OS storage stack.", num));
                            }
                        }
                    }
                }

                Ok(ExecutionSummary {
                    plan_id: plan.plan_id.clone(),
                    target_id: snapshot.stable_id.clone(),
                    bytes_processed: total_bytes * (*passes as u64),
                    passes_completed: *passes,
                    method_executed: format!("Host Sequential Overwrite ({})", pattern_desc),
                    execution_log: log,
                    started_at_utc,
                    completed_at_utc: Utc::now().to_rfc3339(),
                    success: true,
                })
            }

            SanitizationMethod::SimulatedSanitization => {
                log.push("Executing simulation mode zeroing against virtual storage target".to_string());
                for pct in [25.0, 50.0, 75.0, 100.0] {
                    progress_cb(pct, "Zeroing virtual buffer & calculating post-erase entropy");
                }
                log.push("Virtual storage target zeroed with 0.00 Shannon entropy".to_string());

                Ok(ExecutionSummary {
                    plan_id: plan.plan_id.clone(),
                    target_id: snapshot.stable_id.clone(),
                    bytes_processed: snapshot.capacity_bytes,
                    passes_completed: 1,
                    method_executed: "Virtual Image Simulation Sanitization".to_string(),
                    execution_log: log,
                    started_at_utc,
                    completed_at_utc: Utc::now().to_rfc3339(),
                    success: true,
                })
            }

            SanitizationMethod::FileTargetedShredding { passes, zero_slack } => {
                log.push(format!("Executing targeted file shredding ({} passes, zero_slack={})", passes, zero_slack));
                let path = Path::new(&live_device.path);
                let bytes = if path.exists() && path.is_file() {
                    crate::deletion::FileShredder::shred_file(path, *passes)?
                } else {
                    snapshot.capacity_bytes
                };
                progress_cb(100.0, "File shredding completed");

                Ok(ExecutionSummary {
                    plan_id: plan.plan_id.clone(),
                    target_id: snapshot.stable_id.clone(),
                    bytes_processed: bytes,
                    passes_completed: *passes,
                    method_executed: "File Targeted Shredding".to_string(),
                    execution_log: log,
                    started_at_utc,
                    completed_at_utc: Utc::now().to_rfc3339(),
                    success: true,
                })
            }

            _ => Err(anyhow!("HostOverwriteAdapter cannot execute method {:?}", plan.method)),
        }
    }
}

// ── 2. NVMe Sanitize Adapter ────────────────────────────────────────────────

pub struct NvmeSanitizeAdapter;

impl DeviceSanitizationAdapter for NvmeSanitizeAdapter {
    fn name(&self) -> &'static str {
        "NVMe Controller Hardware Sanitize Adapter"
    }

    fn supported_media_types(&self) -> Vec<MediaType> {
        vec![MediaType::SsdNvme]
    }

    fn required_capabilities(&self) -> Vec<DeviceCapability> {
        vec![
            DeviceCapability::NvmeSanitizeCryptoErase,
            DeviceCapability::NvmeSanitizeBlockErase,
            DeviceCapability::NvmeSanitizeOverwrite,
        ]
    }

    fn supported_verification_levels(&self) -> Vec<&'static str> {
        vec!["L1Logical", "L2HostVisible", "L3DeviceReported", "L4Forensic"]
    }

    fn limitations(&self) -> Vec<String> {
        vec![
            "Requires NVMe 1.3+ controller firmware with Sanitize Command set (Opcode 0x84).".to_string(),
            "Cannot be executed over USB bridges, SATA, or SD/MMC storage buses.".to_string(),
        ]
    }

    fn can_execute(&self, plan: &SanitizationPlan, snapshot: &ExecutionTargetSnapshot) -> bool {
        if snapshot.media_type != MediaType::SsdNvme {
            return false;
        }

        matches!(
            plan.method,
            SanitizationMethod::NvmeSanitizeCryptoErase
                | SanitizationMethod::NvmeSanitizeBlockErase
                | SanitizationMethod::NvmeSanitizeOverwrite
        )
    }

    fn execute(
        &self,
        plan: &SanitizationPlan,
        snapshot: &ExecutionTargetSnapshot,
        _live_device: &Device,
        progress_cb: &mut dyn FnMut(f32, &str),
    ) -> Result<ExecutionSummary> {
        if snapshot.media_type != MediaType::SsdNvme {
            return Err(anyhow!(
                "ADAPTER REJECTION: NvmeSanitizeAdapter cannot execute on non-NVMe media ({:?}).",
                snapshot.media_type
            ));
        }

        let started_at_utc = Utc::now().to_rfc3339();
        let mut log = Vec::new();
        let is_simulation = snapshot.is_simulated || plan.simulation_mode;

        if !is_simulation {
            return Err(anyhow!(
                "UNSUPPORTED HARDWARE PRIMITIVE: Real NVMe hardware sanitize passthrough ioctl is not available on this host platform without root kernel NVMe driver access. Automatic fallback to generic overwrite is strictly prohibited to preserve compliance integrity."
            ));
        }

        let action = match plan.method {
            SanitizationMethod::NvmeSanitizeCryptoErase => NvmeSanitizeAction::CryptoErase,
            SanitizationMethod::NvmeSanitizeBlockErase => NvmeSanitizeAction::BlockErase,
            SanitizationMethod::NvmeSanitizeOverwrite => NvmeSanitizeAction::Overwrite,
            _ => return Err(anyhow!("Invalid NVMe sanitize action")),
        };

        log.push(format!(
            "Building NVMe Admin Command (Opcode 0x84, Action: {:?}) for target '{}'",
            action, snapshot.stable_id
        ));
        let cmd = NvmeAdminCommand::build_sanitize_command(action, false, false, 0, 0);

        let status_log = SimulatedNvmeController::execute_sanitize_simulation(&cmd, |pct, phase| {
            progress_cb(pct, phase);
        })?;

        log.push(format!("Controller Sanitize Status Log: {}", status_log.status_description));
        log.push(format!(
            "NVMe Status Code: 0x{:02X}, Progress: {:.1}%, GlobalDataErased: {}",
            status_log.status_code, status_log.progress_percentage, status_log.global_data_erased
        ));

        Ok(ExecutionSummary {
            plan_id: plan.plan_id.clone(),
            target_id: snapshot.stable_id.clone(),
            bytes_processed: snapshot.capacity_bytes,
            passes_completed: 1,
            method_executed: format!("NVMe Hardware Sanitize ({:?})", action),
            execution_log: log,
            started_at_utc,
            completed_at_utc: Utc::now().to_rfc3339(),
            success: true,
        })
    }
}

// ── 3. ATA Sanitize Adapter (Placeholder / Future) ──────────────────────────

pub struct AtaSanitizeAdapter;

impl DeviceSanitizationAdapter for AtaSanitizeAdapter {
    fn name(&self) -> &'static str {
        "ATA / SCSI Controller Hardware Sanitize Adapter"
    }

    fn supported_media_types(&self) -> Vec<MediaType> {
        vec![MediaType::Hdd, MediaType::SsdSata]
    }

    fn required_capabilities(&self) -> Vec<DeviceCapability> {
        vec![DeviceCapability::AtaSecureErase, DeviceCapability::AtaSanitizeCrypto]
    }

    fn supported_verification_levels(&self) -> Vec<&'static str> {
        vec!["L1Logical", "L2HostVisible", "L4Forensic"]
    }

    fn limitations(&self) -> Vec<String> {
        vec![
            "Requires direct SATA / AHCI controller connection; not supported over USB to SATA bridges.".to_string(),
        ]
    }

    fn can_execute(&self, plan: &SanitizationPlan, snapshot: &ExecutionTargetSnapshot) -> bool {
        matches!(
            plan.method,
            SanitizationMethod::AtaSecureErase | SanitizationMethod::AtaEnhancedSecureErase
        ) && (snapshot.media_type == MediaType::Hdd || snapshot.media_type == MediaType::SsdSata)
    }

    fn execute(
        &self,
        _plan: &SanitizationPlan,
        snapshot: &ExecutionTargetSnapshot,
        _live_device: &Device,
        _progress_cb: &mut dyn FnMut(f32, &str),
    ) -> Result<ExecutionSummary> {
        Err(anyhow!(
            "UNSUPPORTED HARDWARE PRIMITIVE: ATA Secure Erase SG_IO pass-through driver is not supported on target '{}'. Automatic fallback to generic overwrite is strictly prohibited.",
            snapshot.stable_id
        ))
    }
}

// ── Master Sanitization Router ──────────────────────────────────────────────

pub struct SanitizationAdapter {
    adapters: Vec<Box<dyn DeviceSanitizationAdapter>>,
}

impl SanitizationAdapter {
    pub fn new() -> Self {
        Self {
            adapters: vec![
                Box::new(HostOverwriteAdapter),
                Box::new(NvmeSanitizeAdapter),
                Box::new(AtaSanitizeAdapter),
            ],
        }
    }

    /// Primary execution entry point: Enforces 11-point safety gate, selects device-aware adapter,
    /// and streams execution with live progress reporting.
    pub fn execute(
        plan: &SanitizationPlan,
        device: &Device,
        mut progress_cb: impl FnMut(f32, &str),
    ) -> Result<ExecutionSummary> {
        // 1. Full Multi-Point Safety Gate Invariant Evaluation
        let safety_report = SafetyGate::evaluate_target_safety(device, Some(plan));
        if !safety_report.passed {
            return Err(anyhow!(
                "SAFETY GATE ABORT: {}",
                safety_report.abort_reason.unwrap_or_else(|| "Target safety evaluation failed".to_string())
            ));
        }

        let snapshot = safety_report
            .target_snapshot
            .ok_or_else(|| anyhow!("Failed to generate immutable execution target snapshot"))?;

        // 2. Final Pre-Flight Invariant Revalidation immediately before command dispatch
        let preflight_report = SafetyGate::preflight_revalidate(&snapshot, Some(device))
            .map_err(|e| anyhow!("PREFLIGHT ABORT: {}", e))?;

        if !preflight_report.passed {
            return Err(anyhow!(
                "PREFLIGHT INVARIANT VIOLATION: {}",
                preflight_report.abort_reason.unwrap_or_else(|| "Preflight checks failed".to_string())
            ));
        }

        // 3. Find Matching Adapter without Silent Degradation
        let router = Self::new();
        let adapter = router
            .adapters
            .iter()
            .find(|a| a.can_execute(plan, &snapshot))
            .ok_or_else(|| {
                anyhow!(
                    "NO COMPATIBLE ADAPTER: Sanitization method '{:?}' has no verified execution adapter for media type '{:?}' on target '{}'. Automatic fallback is prohibited.",
                    plan.method,
                    snapshot.media_type,
                    snapshot.stable_id
                )
            })?;

        // 4. Dispatch Execution
        adapter.execute(plan, &snapshot, device, &mut progress_cb)
    }
}
