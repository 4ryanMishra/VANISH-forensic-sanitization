use crate::common::device::{Device, DeviceCapability, MediaType};
use crate::common::sanitization::{SanitizationMethod, SanitizationPlan, SanitizationStandard};
use uuid::Uuid;

pub struct PolicyEngine;

impl PolicyEngine {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates device classification, interface, and hardware capabilities to recommend an optimal, safe SanitizationPlan.
    /// Strictly respects the physical laboratory limitations:
    /// - SanDisk USB is treated as USB mass-storage (Host overwrite only).
    /// - Simulated NVMe SSD uses genuine NVMe Sanitize/Crypto Erase commands in simulation mode.
    /// - Host system disks generate severe safety warnings.
    pub fn recommend_plan(&self, device: &Device, standard: SanitizationStandard) -> SanitizationPlan {
        let is_simulated = device.stable_id.starts_with("disk-sim-")
            || device.stable_id.starts_with("disk-vdisk-")
            || device.media_type == MediaType::VirtualDisk;

        let (method, rationale, warnings, est_seconds) = match (&device.media_type, &standard) {
            // NVMe SSD: Purge Standard (NIST Purge / IEEE 2883 Purge)
            (MediaType::SsdNvme, SanitizationStandard::Nist80088Purge)
            | (MediaType::SsdNvme, SanitizationStandard::Ieee2883Purge) => {
                if device.capabilities.contains(&DeviceCapability::NvmeSanitizeCryptoErase) {
                    (
                        SanitizationMethod::NvmeSanitizeCryptoErase,
                        "Hardware NVMe Sanitize (Crypto Erase) alters internal controller encryption keys, instantly rendering all user-addressable and over-provisioned NAND blocks unrecoverable.".to_string(),
                        if is_simulated {
                            vec!["Executing real NVMe Sanitize command structure against simulated NVMe controller fixture.".to_string()]
                        } else {
                            vec!["Requires NVMe 1.3+ compliant sanitize command set without frozen security state.".to_string()]
                        },
                        15, // Fast cryptographic key wipe (~seconds)
                    )
                } else if device.capabilities.contains(&DeviceCapability::NvmeSanitizeBlockErase) {
                    (
                        SanitizationMethod::NvmeSanitizeBlockErase,
                        "Hardware NVMe Sanitize (Block Erase) alters physical voltage states across all NAND blocks including wear-leveling spare area.".to_string(),
                        vec![],
                        30,
                    )
                } else {
                    (
                        SanitizationMethod::HostSequentialOverwrite {
                            passes: 1,
                            pattern_desc: "Single-pass random stream".to_string(),
                        },
                        "Fallback host-level overwrite. NOTE: FTL wear-leveling on SSDs may leave retired or over-provisioned NAND blocks untouched.".to_string(),
                        vec!["Host-level overwrite on SSDs cannot guarantee cell-level physical erasure of unmapped blocks.".to_string()],
                        (device.capacity_bytes / (50 * 1024 * 1024)).max(10),
                    )
                }
            }

            // Magnetic HDD: DoD 3-Pass Overwrite
            (MediaType::Hdd, SanitizationStandard::Dod522022M3Pass) => (
                SanitizationMethod::HostSequentialOverwrite {
                    passes: 3,
                    pattern_desc: "Pass 1: 0x00, Pass 2: 0xFF, Pass 3: Pseudo-random stream".to_string(),
                },
                "DoD 5220.22-M magnetic media sanitization protocol (3 passes with inversion and random stream).".to_string(),
                vec!["High write wear; extended execution duration on large mechanical media.".to_string()],
                (device.capacity_bytes * 3 / (40 * 1024 * 1024)).max(30),
            ),

            // USB Flash Media (e.g. 16GB SanDisk Lab USB)
            (MediaType::UsbFlash, _) => {
                let passes = match standard {
                    SanitizationStandard::Dod522022M3Pass => 3,
                    _ => 1,
                };
                (
                    SanitizationMethod::HostSequentialOverwrite {
                        passes,
                        pattern_desc: match standard {
                            SanitizationStandard::Dod522022M3Pass => "DoD 3-Pass (0x00, 0xFF, Random)".to_string(),
                            SanitizationStandard::SinglePassRandom => "Cryptographic pseudo-random stream".to_string(),
                            _ => "Fixed zero stream (0x00)".to_string(),
                        },
                    },
                    "Host sequential block overwrite. Suitable for removable USB flash media. Note that internal flash FTL wear-leveling reserve blocks are out-of-band.".to_string(),
                    vec![
                        "USB mass storage interface does not support hardware NVMe/ATA Sanitize commands.".to_string(),
                        "Physical NAND cells in retired flash spare blocks cannot be directly addressed via host USB commands.".to_string(),
                    ],
                    (device.capacity_bytes * (passes as u64) / (20 * 1024 * 1024)).max(10), // ~20MB/s USB 2/3 flash write speed
                )
            }

            // Virtual Lab Disk
            (MediaType::VirtualDisk, _) => (
                SanitizationMethod::SimulatedSanitization,
                "In-memory virtual disk sanitization with zeroing and entropy validation.".to_string(),
                vec!["Laboratory simulation target; safe for testing and benchmarking.".to_string()],
                5,
            ),

            // Default Clear (NIST Clear)
            _ => (
                SanitizationMethod::HostSequentialOverwrite {
                    passes: 1,
                    pattern_desc: "Single pass zero stream (0x00)".to_string(),
                },
                "NIST SP 800-88 Rev 1 Clear: Sequential logical overwrite of all addressable storage blocks.".to_string(),
                vec![],
                (device.capacity_bytes / (50 * 1024 * 1024)).max(10),
            ),
        };

        let mut final_warnings = warnings;
        if device.system_disk || device.boot_device {
            final_warnings.insert(
                0,
                "CRITICAL: Target is the host system/boot disk. The safety gate will permanently reject execution."
                    .to_string(),
            );
        }

        SanitizationPlan {
            plan_id: format!("plan-{}", Uuid::new_v4().to_string().chars().take(8).collect::<String>()),
            target_id: device.stable_id.clone(),
            standard,
            method,
            rationale,
            prerequisites: vec![
                "Re-verify physical device serial number".to_string(),
                "Confirm target volume is unmounted".to_string(),
                "Ensure target is not host boot/system drive".to_string(),
            ],
            warnings: final_warnings,
            estimated_duration_seconds: Some(est_seconds),
            verification_levels_planned: vec![
                "L1_LOGICAL".to_string(),
                "L2_HOST_VISIBLE".to_string(),
                "L4_FORENSIC".to_string(),
            ],
            simulation_mode: is_simulated,
        }
    }
}
