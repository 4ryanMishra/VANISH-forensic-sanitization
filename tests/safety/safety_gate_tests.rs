#[cfg(test)]
mod tests {
    use vanish_lib::common::device::{Device, InterfaceType, MediaType};
    use vanish_lib::device::{SafetyError, SafetyGate};

    #[test]
    fn test_safety_gate_blocks_host_system_disk() {
        let sys_disk = Device {
            stable_id: "dev-sys-99".to_string(),
            path: "/dev/nvme0n1".to_string(),
            model: "Host Primary System Disk".to_string(),
            serial: "SYS-PROTECTED-88".to_string(),
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

        let result = SafetyGate::assert_safe_for_sanitization(&sys_disk);
        assert!(matches!(result, Err(SafetyError::SystemDiskProtection(_))));
    }

    #[test]
    fn test_safety_gate_blocks_mounted_disks() {
        let mounted_dev = Device {
            stable_id: "dev-mount-01".to_string(),
            path: "/dev/sdc1".to_string(),
            model: "Mounted USB".to_string(),
            serial: "USB-MOUNTED-77".to_string(),
            capacity_bytes: 8_000_000_000,
            logical_block_size: 512,
            physical_block_size: 512,
            interface: InterfaceType::Usb,
            media_type: MediaType::UsbFlash,
            mounted: true,
            mount_points: vec!["/mnt/data".to_string()],
            boot_device: false,
            system_disk: false,
            read_only: false,
            capabilities: vec![],
        };

        let result = SafetyGate::assert_safe_for_sanitization(&mounted_dev);
        assert!(matches!(result, Err(SafetyError::DeviceMounted(_, _))));
    }

    #[test]
    fn test_safety_gate_serial_verification_fails_on_tampering() {
        let dev = Device {
            stable_id: "dev-valid-01".to_string(),
            path: "/dev/sdb".to_string(),
            model: "SanDisk Ultra".to_string(),
            serial: "ACTUAL-SERIAL-11".to_string(),
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

        let result = SafetyGate::verify_device_identity("CONFIRMED-SERIAL-22", &dev);
        assert!(matches!(result, Err(SafetyError::IdentityMismatch(_, _))));
    }
}
