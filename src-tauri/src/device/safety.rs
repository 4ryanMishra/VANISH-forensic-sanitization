use crate::common::device::Device;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SafetyError {
    #[error("Target device '{0}' is the active system/boot disk. Operation strictly blocked.")]
    SystemDiskProtection(String),
    #[error("Device '{0}' is currently mounted at '{1}'. Unmount required before sanitization.")]
    DeviceMounted(String, String),
    #[error("Device '{0}' is marked read-only.")]
    ReadOnlyDevice(String),
    #[error("Device identity verification failed: expected serial '{0}', got '{1}'.")]
    IdentityMismatch(String, String),
}

pub struct SafetyGate;

impl SafetyGate {
    pub fn assert_safe_for_sanitization(device: &Device) -> Result<(), SafetyError> {
        if device.boot_device || device.system_disk {
            return Err(SafetyError::SystemDiskProtection(device.path.clone()));
        }
        if device.mounted && !device.mount_points.is_empty() {
            return Err(SafetyError::DeviceMounted(
                device.path.clone(),
                device.mount_points.join(", "),
            ));
        }
        if device.read_only {
            return Err(SafetyError::ReadOnlyDevice(device.path.clone()));
        }
        Ok(())
    }

    pub fn verify_device_identity(expected_serial: &str, current_device: &Device) -> Result<(), SafetyError> {
        if current_device.serial != expected_serial {
            return Err(SafetyError::IdentityMismatch(
                expected_serial.to_string(),
                current_device.serial.clone(),
            ));
        }
        Ok(())
    }
}
