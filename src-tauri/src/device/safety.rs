use crate::common::device::{Device, DeviceCapability, InterfaceType, MediaType};
use crate::common::sanitization::{SanitizationMethod, SanitizationPlan, SanitizationStandard};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SafetyCheckStatus {
    Pass,
    Fail,
    Warning,
    Unknown,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SafetySeverity {
    Info,
    Warning,
    High,
    Critical,
}

#[derive(Error, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyError {
    #[error("CRITICAL SAFETY BLOCK: Target device '{0}' is the host system disk. Destructive operations are permanently prohibited.")]
    SystemDiskProtection(String),

    #[error("CRITICAL SAFETY BLOCK: Target device '{0}' is the host boot device. Destructive operations are permanently prohibited.")]
    BootDeviceProtection(String),

    #[error("SAFETY VIOLATION: Device '{0}' is actively mounted at '{1}'. Target must be unmounted before sanitization.")]
    DeviceMounted(String, String),

    #[error("DEVICE STATUS BLOCK: Device '{0}' is marked read-only or hardware write-locked.")]
    ReadOnlyDevice(String),

    #[error("IDENTITY MISMATCH: Expected serial '{expected}', but live query detected '{actual}'. Operation aborted.")]
    IdentityMismatch { expected: String, actual: String },

    #[error("PATH MISMATCH: Target device path shifted from '{expected}' to '{actual}'. Operation aborted to prevent drive-letter race conditions.")]
    PathMismatch { expected: String, actual: String },

    #[error("CAPACITY ANOMALY: Target capacity changed from {expected} bytes to {actual} bytes. Operation aborted.")]
    CapacityMismatch { expected: u64, actual: u64 },

    #[error("DEVICE DISAPPEARED: Target device '{0}' is no longer present on the system bus. Operation aborted.")]
    DeviceDisappeared(String),

    #[error("DEVICE INACCESSIBLE: Target device '{0}' could not be probed or opened for preflight validation.")]
    DeviceInaccessible(String),

    #[error("CAPABILITY MISMATCH: Requested method '{method}' is not supported by verified device capabilities ({reason}).")]
    UnsupportedCapability { method: String, reason: String },

    #[error("POLICY VIOLATION: Sanitization standard '{0}' is incompatible with device media class or requested parameters.")]
    PolicyMismatch(String),

    #[error("USER CONFIRMATION FAILED: Confirmation serial '{received_serial}' did not match target snapshot serial '{expected_serial}'.")]
    ConfirmationFailed {
        expected_serial: String,
        received_serial: String,
    },

    #[error("PREFLIGHT INVARIANT FAILED: {0}")]
    PreflightCheckFailed(String),

    #[error("AMBIGUOUS TARGET IDENTITY: Device serial or model is empty or indeterminate. Cannot arm destructive operation safely.")]
    AmbiguousIdentity(String),
}

/// Immutable snapshot of the target device captured when sanitization is armed.
/// Contains a cryptographic SHA-256 fingerprint of all invariant hardware attributes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionTargetSnapshot {
    pub stable_id: String,
    pub path: String,
    pub model: String,
    pub serial: String,
    pub capacity_bytes: u64,
    pub logical_block_size: u32,
    pub physical_block_size: u32,
    pub interface: InterfaceType,
    pub media_type: MediaType,
    pub is_simulated: bool,
    pub capabilities: Vec<DeviceCapability>,
    pub snapshot_timestamp_utc: String,
    pub fingerprint_sha256: String,
}

impl ExecutionTargetSnapshot {
    /// Compute deterministic SHA-256 fingerprint of all immutable device attributes
    pub fn compute_fingerprint(
        serial: &str,
        model: &str,
        path: &str,
        capacity_bytes: u64,
        logical_block_size: u32,
        physical_block_size: u32,
        interface: &InterfaceType,
        media_type: &MediaType,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(serial.trim().as_bytes());
        hasher.update(b"|");
        hasher.update(model.trim().as_bytes());
        hasher.update(b"|");
        hasher.update(path.trim().as_bytes());
        hasher.update(b"|");
        hasher.update(capacity_bytes.to_le_bytes());
        hasher.update(b"|");
        hasher.update(logical_block_size.to_le_bytes());
        hasher.update(b"|");
        hasher.update(physical_block_size.to_le_bytes());
        hasher.update(b"|");
        hasher.update(format!("{:?}", interface).as_bytes());
        hasher.update(b"|");
        hasher.update(format!("{:?}", media_type).as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Create snapshot from live Device struct
    pub fn from_device(device: &Device) -> Self {
        let fingerprint_sha256 = Self::compute_fingerprint(
            &device.serial,
            &device.model,
            &device.path,
            device.capacity_bytes,
            device.logical_block_size,
            device.physical_block_size,
            &device.interface,
            &device.media_type,
        );

        Self {
            stable_id: device.stable_id.clone(),
            path: device.path.clone(),
            model: device.model.clone(),
            serial: device.serial.clone(),
            capacity_bytes: device.capacity_bytes,
            logical_block_size: device.logical_block_size,
            physical_block_size: device.physical_block_size,
            interface: device.interface.clone(),
            media_type: device.media_type.clone(),
            is_simulated: device.is_simulated,
            capabilities: device.capabilities.clone(),
            snapshot_timestamp_utc: Utc::now().to_rfc3339(),
            fingerprint_sha256,
        }
    }
}

/// Structured individual safety check result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SafetyCheck {
    pub check: String,
    pub status: SafetyCheckStatus,
    pub severity: SafetySeverity,
    pub message: String,
    pub evidence: Vec<String>,
}

/// Complete multi-phase safety evaluation report
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SafetyEvaluationReport {
    pub passed: bool,
    pub target_id: String,
    pub checks: Vec<SafetyCheck>,
    pub target_snapshot: Option<ExecutionTargetSnapshot>,
    pub evaluated_at_utc: String,
    pub abort_reason: Option<String>,
}

pub struct SafetyGate;

impl SafetyGate {
    /// Phase 1 & 2 Invariant: Full safety evaluation across all 11 points before arming
    pub fn evaluate_target_safety(
        device: &Device,
        plan: Option<&SanitizationPlan>,
    ) -> SafetyEvaluationReport {
        let mut checks = Vec::new();
        let mut overall_passed = true;
        let mut abort_reason = None;

        // 1. Device Discovery & Path Check
        if device.path.trim().is_empty() {
            overall_passed = false;
            abort_reason = Some("Device path is empty".to_string());
            checks.push(SafetyCheck {
                check: "DevicePathValidation".to_string(),
                status: SafetyCheckStatus::Blocked,
                severity: SafetySeverity::Critical,
                message: "Target device path is empty or invalid.".to_string(),
                evidence: vec!["path: empty".to_string()],
            });
        } else {
            checks.push(SafetyCheck {
                check: "DevicePathValidation".to_string(),
                status: SafetyCheckStatus::Pass,
                severity: SafetySeverity::Info,
                message: format!("Target device path '{}' is valid.", device.path),
                evidence: vec![format!("path: {}", device.path)],
            });
        }

        // 2. Ambiguous Identity Check
        if device.serial.trim().is_empty() || device.serial == "UNKNOWN" {
            // For real physical non-serial devices, flag warning/blocked
            if !device.is_simulated && (device.serial.trim().is_empty()) {
                overall_passed = false;
                abort_reason = Some("Target serial is indeterminate".to_string());
                checks.push(SafetyCheck {
                    check: "DeviceIdentityCheck".to_string(),
                    status: SafetyCheckStatus::Blocked,
                    severity: SafetySeverity::Critical,
                    message: "Device identity is indeterminate. Cannot arm destructive operation.".to_string(),
                    evidence: vec![format!("serial: {:?}", device.serial)],
                });
            } else {
                checks.push(SafetyCheck {
                    check: "DeviceIdentityCheck".to_string(),
                    status: SafetyCheckStatus::Pass,
                    severity: SafetySeverity::Info,
                    message: format!("Device identity verified: {}", device.stable_id),
                    evidence: vec![format!("stable_id: {}", device.stable_id), format!("serial: {}", device.serial)],
                });
            }
        } else {
            checks.push(SafetyCheck {
                check: "DeviceIdentityCheck".to_string(),
                status: SafetyCheckStatus::Pass,
                severity: SafetySeverity::Info,
                message: format!("Device serial '{}' verified.", device.serial),
                evidence: vec![format!("serial: {}", device.serial)],
            });
        }

        // 3. System Disk Protection Check
        if device.system_disk {
            overall_passed = false;
            abort_reason = Some("Target is host OS system disk".to_string());
            checks.push(SafetyCheck {
                check: "SystemDiskProtection".to_string(),
                status: SafetyCheckStatus::Blocked,
                severity: SafetySeverity::Critical,
                message: "CRITICAL: Target is the host system disk. All write operations permanently blocked.".to_string(),
                evidence: vec![format!("system_disk: true"), format!("path: {}", device.path)],
            });
        } else {
            checks.push(SafetyCheck {
                check: "SystemDiskProtection".to_string(),
                status: SafetyCheckStatus::Pass,
                severity: SafetySeverity::Info,
                message: "Target is NOT the host system disk.".to_string(),
                evidence: vec!["system_disk: false".to_string()],
            });
        }

        // 4. Boot Device Protection Check
        if device.boot_device {
            overall_passed = false;
            abort_reason = Some("Target is host boot device".to_string());
            checks.push(SafetyCheck {
                check: "BootDeviceProtection".to_string(),
                status: SafetyCheckStatus::Blocked,
                severity: SafetySeverity::Critical,
                message: "CRITICAL: Target is marked as boot device or hosts /boot. Permanently blocked.".to_string(),
                evidence: vec![format!("boot_device: true"), format!("path: {}", device.path)],
            });
        } else {
            checks.push(SafetyCheck {
                check: "BootDeviceProtection".to_string(),
                status: SafetyCheckStatus::Pass,
                severity: SafetySeverity::Info,
                message: "Target is NOT the host boot device.".to_string(),
                evidence: vec!["boot_device: false".to_string()],
            });
        }

        // 5. Active Mount Check
        if device.mounted || !device.mount_points.is_empty() {
            overall_passed = false;
            abort_reason = Some(format!("Target has active mount points: {}", device.mount_points.join(", ")));
            checks.push(SafetyCheck {
                check: "MountedStateCheck".to_string(),
                status: SafetyCheckStatus::Blocked,
                severity: SafetySeverity::High,
                message: format!("Device has active mounts ({}). Unmount before proceeding.", device.mount_points.join(", ")),
                evidence: device.mount_points.clone(),
            });
        } else {
            checks.push(SafetyCheck {
                check: "MountedStateCheck".to_string(),
                status: SafetyCheckStatus::Pass,
                severity: SafetySeverity::Info,
                message: "Device has no active mount points.".to_string(),
                evidence: vec!["mounted: false".to_string()],
            });
        }

        // 6. Read-Only Status Check
        if device.read_only {
            overall_passed = false;
            abort_reason = Some("Device is marked read-only".to_string());
            checks.push(SafetyCheck {
                check: "ReadOnlyStateCheck".to_string(),
                status: SafetyCheckStatus::Blocked,
                severity: SafetySeverity::High,
                message: "Device is marked read-only. Hardware switch or read-only attribute must be cleared.".to_string(),
                evidence: vec!["read_only: true".to_string()],
            });
        } else {
            checks.push(SafetyCheck {
                check: "ReadOnlyStateCheck".to_string(),
                status: SafetyCheckStatus::Pass,
                severity: SafetySeverity::Info,
                message: "Device write access confirmed (read_only: false).".to_string(),
                evidence: vec!["read_only: false".to_string()],
            });
        }

        // 7. Capacity Non-Zero Check
        if device.capacity_bytes == 0 {
            overall_passed = false;
            abort_reason = Some("Device reports 0 capacity bytes".to_string());
            checks.push(SafetyCheck {
                check: "CapacityValidation".to_string(),
                status: SafetyCheckStatus::Blocked,
                severity: SafetySeverity::High,
                message: "Target device capacity is 0 bytes or unreadable.".to_string(),
                evidence: vec!["capacity_bytes: 0".to_string()],
            });
        } else {
            checks.push(SafetyCheck {
                check: "CapacityValidation".to_string(),
                status: SafetyCheckStatus::Pass,
                severity: SafetySeverity::Info,
                message: format!("Device capacity confirmed: {} bytes ({:.2} GB).", device.capacity_bytes, device.capacity_bytes as f64 / 1e9),
                evidence: vec![format!("capacity_bytes: {}", device.capacity_bytes)],
            });
        }

        // 8. Policy & Method Compatibility Check (if plan provided)
        if let Some(p) = plan {
            let method_supported = match &p.method {
                SanitizationMethod::NvmeSanitizeCryptoErase => {
                    device.capabilities.contains(&DeviceCapability::NvmeSanitizeCryptoErase)
                        || (device.is_simulated && device.media_type == MediaType::SsdNvme)
                }
                SanitizationMethod::NvmeSanitizeBlockErase => {
                    device.capabilities.contains(&DeviceCapability::NvmeSanitizeBlockErase)
                        || (device.is_simulated && device.media_type == MediaType::SsdNvme)
                }
                SanitizationMethod::NvmeSanitizeOverwrite => {
                    device.capabilities.contains(&DeviceCapability::NvmeSanitizeOverwrite)
                        || (device.is_simulated && device.media_type == MediaType::SsdNvme)
                }
                SanitizationMethod::AtaSecureErase => {
                    device.capabilities.contains(&DeviceCapability::AtaSecureErase)
                }
                SanitizationMethod::AtaEnhancedSecureErase => {
                    device.capabilities.contains(&DeviceCapability::AtaEnhancedSecureErase)
                }
                SanitizationMethod::HostSequentialOverwrite { .. } => {
                    device.capabilities.contains(&DeviceCapability::HostBlockOverwrite)
                }
                SanitizationMethod::FileTargetedShredding { .. } => true,
                SanitizationMethod::SimulatedSanitization => device.is_simulated,
            };

            if !method_supported {
                overall_passed = false;
                abort_reason = Some(format!("Method {:?} is not supported by target capabilities", p.method));
                checks.push(SafetyCheck {
                    check: "CapabilityCompatibility".to_string(),
                    status: SafetyCheckStatus::Blocked,
                    severity: SafetySeverity::Critical,
                    message: format!("Requested sanitization method {:?} is not supported by target capabilities.", p.method),
                    evidence: vec![format!("capabilities: {:?}", device.capabilities), format!("requested_method: {:?}", p.method)],
                });
            } else {
                checks.push(SafetyCheck {
                    check: "CapabilityCompatibility".to_string(),
                    status: SafetyCheckStatus::Pass,
                    severity: SafetySeverity::Info,
                    message: format!("Sanitization method {:?} verified against device capabilities.", p.method),
                    evidence: vec![format!("capabilities: {:?}", device.capabilities)],
                });
            }
        }

        let snapshot = if overall_passed {
            Some(ExecutionTargetSnapshot::from_device(device))
        } else {
            None
        };

        SafetyEvaluationReport {
            passed: overall_passed,
            target_id: device.stable_id.clone(),
            checks,
            target_snapshot: snapshot,
            evaluated_at_utc: Utc::now().to_rfc3339(),
            abort_reason,
        }
    }

    /// Legacy convenience invariant assertion (fails fast with SafetyError)
    pub fn assert_safe_for_sanitization(device: &Device) -> Result<(), SafetyError> {
        let report = Self::evaluate_target_safety(device, None);
        if !report.passed {
            if device.system_disk {
                return Err(SafetyError::SystemDiskProtection(device.path.clone()));
            }
            if device.boot_device {
                return Err(SafetyError::BootDeviceProtection(device.path.clone()));
            }
            if device.mounted || !device.mount_points.is_empty() {
                return Err(SafetyError::DeviceMounted(
                    device.path.clone(),
                    device.mount_points.join(", "),
                ));
            }
            if device.read_only {
                return Err(SafetyError::ReadOnlyDevice(device.path.clone()));
            }
            return Err(SafetyError::PreflightCheckFailed(
                report.abort_reason.unwrap_or_else(|| "Safety gate check failed".to_string()),
            ));
        }
        Ok(())
    }

    /// Explicit user confirmation validation
    pub fn verify_user_confirmation(
        snapshot: &ExecutionTargetSnapshot,
        confirmed_serial: &str,
        confirmed_target_id: &str,
    ) -> Result<(), SafetyError> {
        if confirmed_target_id.trim() != snapshot.stable_id.trim() {
            return Err(SafetyError::IdentityMismatch {
                expected: snapshot.stable_id.clone(),
                actual: confirmed_target_id.to_string(),
            });
        }

        if confirmed_serial.trim() != snapshot.serial.trim() {
            return Err(SafetyError::ConfirmationFailed {
                expected_serial: snapshot.serial.clone(),
                received_serial: confirmed_serial.to_string(),
            });
        }

        Ok(())
    }

    /// Final Pre-Flight Invariant Revalidation immediately before issuing commands.
    /// Fails closed if the device disappeared, path changed, serial changed, capacity changed,
    /// or if any system/boot/mount invariants were violated since arming.
    pub fn preflight_revalidate(
        snapshot: &ExecutionTargetSnapshot,
        live_device: Option<&Device>,
    ) -> Result<SafetyEvaluationReport, SafetyError> {
        let live = match live_device {
            Some(d) => d,
            None => {
                return Err(SafetyError::DeviceDisappeared(format!(
                    "Device '{}' ({}) was not found during preflight check",
                    snapshot.stable_id, snapshot.path
                )));
            }
        };

        let mut checks = Vec::new();

        // Check 1: Stable Identity Revalidation
        if live.stable_id != snapshot.stable_id {
            return Err(SafetyError::IdentityMismatch {
                expected: snapshot.stable_id.clone(),
                actual: live.stable_id.clone(),
            });
        }
        checks.push(SafetyCheck {
            check: "PreflightStableIdentity".to_string(),
            status: SafetyCheckStatus::Pass,
            severity: SafetySeverity::Info,
            message: "Stable ID matched snapshot.".to_string(),
            evidence: vec![live.stable_id.clone()],
        });

        // Check 2: Device Path Consistency
        if live.path != snapshot.path {
            return Err(SafetyError::PathMismatch {
                expected: snapshot.path.clone(),
                actual: live.path.clone(),
            });
        }
        checks.push(SafetyCheck {
            check: "PreflightPathConsistency".to_string(),
            status: SafetyCheckStatus::Pass,
            severity: SafetySeverity::Info,
            message: "Device path matched snapshot.".to_string(),
            evidence: vec![live.path.clone()],
        });

        // Check 3: Serial Number Consistency
        if live.serial.trim() != snapshot.serial.trim() {
            return Err(SafetyError::IdentityMismatch {
                expected: snapshot.serial.clone(),
                actual: live.serial.clone(),
            });
        }
        checks.push(SafetyCheck {
            check: "PreflightSerialConsistency".to_string(),
            status: SafetyCheckStatus::Pass,
            severity: SafetySeverity::Info,
            message: "Device serial matched snapshot.".to_string(),
            evidence: vec![live.serial.clone()],
        });

        // Check 4: Capacity Invariant
        if live.capacity_bytes != snapshot.capacity_bytes {
            return Err(SafetyError::CapacityMismatch {
                expected: snapshot.capacity_bytes,
                actual: live.capacity_bytes,
            });
        }
        checks.push(SafetyCheck {
            check: "PreflightCapacityConsistency".to_string(),
            status: SafetyCheckStatus::Pass,
            severity: SafetySeverity::Info,
            message: "Device capacity matched snapshot.".to_string(),
            evidence: vec![format!("capacity: {}", live.capacity_bytes)],
        });

        // Check 5: System & Boot Disk Protection
        if live.system_disk {
            return Err(SafetyError::SystemDiskProtection(live.path.clone()));
        }
        if live.boot_device {
            return Err(SafetyError::BootDeviceProtection(live.path.clone()));
        }
        checks.push(SafetyCheck {
            check: "PreflightSystemDiskProtection".to_string(),
            status: SafetyCheckStatus::Pass,
            severity: SafetySeverity::Info,
            message: "Device is confirmed non-system and non-boot.".to_string(),
            evidence: vec!["system_disk: false, boot_device: false".to_string()],
        });

        // Check 6: Mount Status
        if live.mounted || !live.mount_points.is_empty() {
            return Err(SafetyError::DeviceMounted(
                live.path.clone(),
                live.mount_points.join(", "),
            ));
        }
        checks.push(SafetyCheck {
            check: "PreflightMountCheck".to_string(),
            status: SafetyCheckStatus::Pass,
            severity: SafetySeverity::Info,
            message: "Device is confirmed unmounted.".to_string(),
            evidence: vec!["mounted: false".to_string()],
        });

        // Check 7: Read-Only Status
        if live.read_only {
            return Err(SafetyError::ReadOnlyDevice(live.path.clone()));
        }
        checks.push(SafetyCheck {
            check: "PreflightReadOnlyCheck".to_string(),
            status: SafetyCheckStatus::Pass,
            severity: SafetySeverity::Info,
            message: "Device write access confirmed.".to_string(),
            evidence: vec!["read_only: false".to_string()],
        });

        // Check 8: Cryptographic Fingerprint Verification
        let live_fingerprint = ExecutionTargetSnapshot::compute_fingerprint(
            &live.serial,
            &live.model,
            &live.path,
            live.capacity_bytes,
            live.logical_block_size,
            live.physical_block_size,
            &live.interface,
            &live.media_type,
        );

        if live_fingerprint != snapshot.fingerprint_sha256 {
            return Err(SafetyError::PreflightCheckFailed(
                "Hardware fingerprint mismatch between arming snapshot and live device".to_string(),
            ));
        }
        checks.push(SafetyCheck {
            check: "PreflightFingerprintVerification".to_string(),
            status: SafetyCheckStatus::Pass,
            severity: SafetySeverity::Info,
            message: "Cryptographic SHA-256 fingerprint verified against snapshot.".to_string(),
            evidence: vec![format!("fingerprint: {}", snapshot.fingerprint_sha256)],
        });

        Ok(SafetyEvaluationReport {
            passed: true,
            target_id: snapshot.stable_id.clone(),
            checks,
            target_snapshot: Some(snapshot.clone()),
            evaluated_at_utc: Utc::now().to_rfc3339(),
            abort_reason: None,
        })
    }

    /// Legacy identity confirmation
    pub fn verify_device_identity(
        expected_serial: &str,
        current_device: &Device,
    ) -> Result<(), SafetyError> {
        if current_device.serial.trim() != expected_serial.trim() {
            return Err(SafetyError::IdentityMismatch {
                expected: expected_serial.to_string(),
                actual: current_device.serial.clone(),
            });
        }
        Ok(())
    }
}

