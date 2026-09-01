use crate::common::device::Device;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SafetyError {
    #[error("CRITICAL SAFETY BLOCK: Target device '{0}' is the host system/boot disk. Write operations are permanently blocked.")]
    SystemDiskProtection(String),
    #[error("SAFETY VIOLATION: Device '{0}' is mounted at '{1}'. Target must be unmounted before sanitization.")]
    DeviceMounted(String, String),
    #[error("DEVICE STATUS: Device '{0}' is marked read-only.")]
    ReadOnlyDevice(String),
    #[error("IDENTITY MISMATCH: Target re-verification failed. Expected serial '{0}', but detected '{1}'. Operation aborted.")]
    IdentityMismatch(String, String),
    #[error("CAPABILITY MISMATCH: Requested operation requires capability '{0:?}' not supported by device.")]
    UnsupportedCapability(String),
}

pub struct SafetyGate;

impl SafetyGate {
    /// Stage 1 Invariant: Enforce system drive and active filesystem protection.
    pub fn assert_safe_for_sanitization(device: &Device) -> Result<(), SafetyError> {
        if device.boot_device || device.system_disk {
            return Err(SafetyError::SystemDiskProtection(device.path.clone()));
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
        Ok(())
    }

    /// Stage 2 Invariant: Pre-execution identity confirmation.
    /// Re-checks serial number right before arming or issuing destructive commands to prevent drive-letter race conditions.
    pub fn verify_device_identity(expected_serial: &str, current_device: &Device) -> Result<(), SafetyError> {
        if current_device.serial.trim() != expected_serial.trim() {
            return Err(SafetyError::IdentityMismatch(
                expected_serial.to_string(),
                current_device.serial.clone(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::device::{InterfaceType, MediaType};

    #[test]
    fn test_system_disk_is_always_blocked() {
        let sys_dev = Device {
            stable_id: "dev-sys01".to_string(),
            path: "/dev/nvme0n1".to_string(),
            model: "System NVMe".to_string(),
            serial: "SYS-12345".to_string(),
            capacity_bytes: 1_000_000_000_000,
            logical_block_size: 512,
            physical_block_size: 512,
            interface: InterfaceType::Nvme,
            media_type: MediaType::SsdNvme,
            mounted: true,
            mount_points: vec!["/".to_string()],
            boot_device: true,
            system_disk: true,
            read_only: false,
            capabilities: vec![],
        };

        let result = SafetyGate::assert_safe_for_sanitization(&sys_dev);
        assert!(matches!(result, Err(SafetyError::SystemDiskProtection(_))));
    }

    #[test]
    fn test_unmounted_lab_target_passes_safety_gate() {
        let lab_dev = Device {
            stable_id: "dev-lab01".to_string(),
            path: "/dev/sdb".to_string(),
            model: "SanDisk Ultra".to_string(),
            serial: "4C530001230415116032".to_string(),
            capacity_bytes: 16_000_000_000,
            logical_block_size: 512,
            physical_block_size: 512,
            interface: InterfaceType::Usb,
            media_type: MediaType::UsbFlash,
            mounted: false,
            mount_points: vec![],
            boot_device: false,
            system_disk: false,
            read_only: false,
            capabilities: vec![],
        };

        assert_eq!(SafetyGate::assert_safe_for_sanitization(&lab_dev), Ok(()));
    }

    #[test]
    fn test_identity_mismatch_fails_closed() {
        let dev = Device {
            stable_id: "dev-lab01".to_string(),
            path: "/dev/sdb".to_string(),
            model: "SanDisk Ultra".to_string(),
            serial: "CURRENT-SERIAL-99".to_string(),
            capacity_bytes: 16_000_000_000,
            logical_block_size: 512,
            physical_block_size: 512,
            interface: InterfaceType::Usb,
            media_type: MediaType::UsbFlash,
            mounted: false,
            mount_points: vec![],
            boot_device: false,
            system_disk: false,
            read_only: false,
            capabilities: vec![],
        };

        let result = SafetyGate::verify_device_identity("ORIGINAL-SERIAL-00", &dev);
        assert!(matches!(result, Err(SafetyError::IdentityMismatch(_, _))));
    }
}
