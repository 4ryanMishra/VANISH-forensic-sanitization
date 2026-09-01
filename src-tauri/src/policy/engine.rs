use crate::common::device::{Device, DeviceCapability, MediaType};
use crate::common::sanitization::{SanitizationMethod, SanitizationPlan, SanitizationStandard};
use uuid::Uuid;

pub struct PolicyEngine;

impl PolicyEngine {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates device capabilities and standard requirements to produce a hardware-aware sanitization plan
    pub fn recommend_plan(&self, device: &Device, standard: SanitizationStandard) -> SanitizationPlan {
        let (method, rationale, warnings) = match (&device.media_type, &standard) {
            (MediaType::SsdNvme, SanitizationStandard::Nist80088Purge) => {
                if device.capabilities.contains(&DeviceCapability::NvmeSanitizeCryptoErase) {
                    (
                        SanitizationMethod::NvmeSanitizeCryptoErase,
                        "Hardware-level NVMe Cryptographic Erase alters internal encryption keys, invalidating all NAND blocks including over-provisioned space.".to_string(),
                        vec!["Requires NVMe sanitize command support without controller freeze.".to_string()]
                    )
                } else if device.capabilities.contains(&DeviceCapability::NvmeSanitizeBlockErase) {
                    (
                        SanitizationMethod::NvmeSanitizeBlockErase,
                        "Hardware-level NVMe Block Erase performs low-level flash cell voltage discharge across all user-addressable and spare blocks.".to_string(),
                        vec![]
                    )
                } else {
                    (
                        SanitizationMethod::HostSequentialOverwrite { passes: 1, pattern_desc: "Pseudo-random stream".to_string() },
                        "Fallback host-level overwrite. NOTE: FTL wear-leveling may leave residual data in retired or over-provisioned NAND blocks.".to_string(),
                        vec!["Host-level overwrite on SSDs does not guarantee physical cell-level erasure of unmapped blocks.".to_string()]
                    )
                }
            },
            (MediaType::Hdd, SanitizationStandard::Dod522022M3Pass) => {
                (
                    SanitizationMethod::HostSequentialOverwrite {
                        passes: 3,
                        pattern_desc: "Pass 1: 0x00, Pass 2: 0xFF, Pass 3: Random + Verify".to_string(),
                    },
                    "DoD 5220.22-M 3-pass sequential magnetic overwrite with pattern inversion and terminal verification.".to_string(),
                    vec!["High write wear; prolonged execution time on large magnetic media.".to_string()]
                )
            },
            (MediaType::VirtualDisk, _) => {
                (
                    SanitizationMethod::SimulatedSanitization,
                    "Virtual image software sanitization executing in-memory zeroing and entropy validation.".to_string(),
                    vec!["Laboratory simulation mode; no physical hardware affected.".to_string()]
                )
            },
            _ => {
                (
                    SanitizationMethod::HostSequentialOverwrite {
                        passes: 1,
                        pattern_desc: "Single pass fixed zeros (0x00)".to_string(),
                    },
                    "NIST SP 800-88 Rev 1 Clear: Logical overwrite of all addressable storage locations.".to_string(),
                    vec![]
                )
            }
        };

        SanitizationPlan {
            plan_id: format!("plan-{}", Uuid::new_v4().to_string().chars().take(8).collect::<String>()),
            target_id: device.stable_id.clone(),
            standard,
            method,
            rationale,
            prerequisites: vec![
                "Confirm target serial identity".to_string(),
                "Ensure device is not mounted".to_string(),
            ],
            warnings,
            estimated_duration_seconds: Some((device.capacity_bytes / (50 * 1024 * 1024)).max(10)), // assume ~50MB/s baseline
            verification_levels_planned: vec!["L1_LOGICAL".to_string(), "L2_HOST_VISIBLE".to_string(), "L4_FORENSIC".to_string()],
            simulation_mode: device.media_type == MediaType::VirtualDisk,
        }
    }
}
