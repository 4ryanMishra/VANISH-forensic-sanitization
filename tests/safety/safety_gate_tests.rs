#[cfg(test)]
mod tests {
    use vanish_lib::common::device::{Device, DeviceCapability, InterfaceType, MediaType};
    use vanish_lib::common::sanitization::{SanitizationMethod, SanitizationPlan, SanitizationStandard};
    use vanish_lib::device::{
        ExecutionTargetSnapshot, SafetyCheckStatus, SafetyError, SafetyGate,
    };

    fn make_valid_disposable_target() -> Device {
        Device {
            stable_id: "disk-sandisk-16g".to_string(),
            path: "/dev/sdb".to_string(),
            model: "SanDisk Ultra USB 3.0".to_string(),
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
            is_simulated: false,
            capabilities: vec![DeviceCapability::HostBlockOverwrite],
        }
    }

    #[test]
    fn test_safety_gate_blocks_host_system_disk() {
        let mut sys_disk = make_valid_disposable_target();
        sys_disk.path = "/dev/nvme0n1".to_string();
        sys_disk.system_disk = true;

        let report = SafetyGate::evaluate_target_safety(&sys_disk, None);
        assert!(!report.passed);
        assert!(report.target_snapshot.is_none());
        assert!(report.checks.iter().any(|c| c.check == "SystemDiskProtection" && c.status == SafetyCheckStatus::Blocked));

        let res = SafetyGate::assert_safe_for_sanitization(&sys_disk);
        assert!(matches!(res, Err(SafetyError::SystemDiskProtection(_))));
    }

    #[test]
    fn test_safety_gate_blocks_host_boot_device() {
        let mut boot_disk = make_valid_disposable_target();
        boot_disk.boot_device = true;

        let report = SafetyGate::evaluate_target_safety(&boot_disk, None);
        assert!(!report.passed);
        assert!(report.checks.iter().any(|c| c.check == "BootDeviceProtection" && c.status == SafetyCheckStatus::Blocked));

        let res = SafetyGate::assert_safe_for_sanitization(&boot_disk);
        assert!(matches!(res, Err(SafetyError::BootDeviceProtection(_))));
    }

    #[test]
    fn test_safety_gate_blocks_mounted_disks() {
        let mut mounted_dev = make_valid_disposable_target();
        mounted_dev.mounted = true;
        mounted_dev.mount_points = vec!["/media/usb".to_string()];

        let report = SafetyGate::evaluate_target_safety(&mounted_dev, None);
        assert!(!report.passed);
        assert!(report.checks.iter().any(|c| c.check == "MountedStateCheck" && c.status == SafetyCheckStatus::Blocked));

        let res = SafetyGate::assert_safe_for_sanitization(&mounted_dev);
        assert!(matches!(res, Err(SafetyError::DeviceMounted(_, _))));
    }

    #[test]
    fn test_safety_gate_blocks_readonly_target() {
        let mut ro_dev = make_valid_disposable_target();
        ro_dev.read_only = true;

        let report = SafetyGate::evaluate_target_safety(&ro_dev, None);
        assert!(!report.passed);
        assert!(report.checks.iter().any(|c| c.check == "ReadOnlyStateCheck" && c.status == SafetyCheckStatus::Blocked));

        let res = SafetyGate::assert_safe_for_sanitization(&ro_dev);
        assert!(matches!(res, Err(SafetyError::ReadOnlyDevice(_))));
    }

    #[test]
    fn test_valid_disposable_target_evaluates_pass_and_creates_snapshot() {
        let dev = make_valid_disposable_target();
        let plan = SanitizationPlan {
            plan_id: "plan-01".to_string(),
            target_id: dev.stable_id.clone(),
            standard: SanitizationStandard::SinglePassZero,
            method: SanitizationMethod::HostSequentialOverwrite { passes: 1, pattern_desc: "0x00 Zero-Fill".to_string() },
            rationale: "Lab test".to_string(),
            prerequisites: vec![],
            warnings: vec![],
            estimated_duration_seconds: Some(10),
            verification_levels_planned: vec!["L1Logical".to_string()],
            simulation_mode: false,
        };

        let report = SafetyGate::evaluate_target_safety(&dev, Some(&plan));
        assert!(report.passed);
        assert!(report.target_snapshot.is_some());
        let snapshot = report.target_snapshot.unwrap();
        assert_eq!(snapshot.stable_id, dev.stable_id);
        assert_eq!(snapshot.fingerprint_sha256.len(), 64);
    }

    #[test]
    fn test_unsupported_capability_fails_policy_check() {
        let dev = make_valid_disposable_target(); // USB flash with HostBlockOverwrite only
        let plan = SanitizationPlan {
            plan_id: "plan-nvme".to_string(),
            target_id: dev.stable_id.clone(),
            standard: SanitizationStandard::Nist80088Purge,
            method: SanitizationMethod::NvmeSanitizeCryptoErase, // NVMe command on USB flash
            rationale: "Invalid attempt".to_string(),
            prerequisites: vec![],
            warnings: vec![],
            estimated_duration_seconds: Some(5),
            verification_levels_planned: vec![],
            simulation_mode: false,
        };

        let report = SafetyGate::evaluate_target_safety(&dev, Some(&plan));
        assert!(!report.passed, "USB flash cannot execute NVMe Sanitize Crypto Erase");
        assert!(report.checks.iter().any(|c| c.check == "CapabilityCompatibility" && c.status == SafetyCheckStatus::Blocked));
    }

    #[test]
    fn test_user_confirmation_validation() {
        let dev = make_valid_disposable_target();
        let snapshot = ExecutionTargetSnapshot::from_device(&dev);

        // Correct confirmation passes
        assert!(SafetyGate::verify_user_confirmation(&snapshot, "4C530001230415116032", &dev.stable_id).is_ok());

        // Wrong serial fails closed
        let wrong_serial = SafetyGate::verify_user_confirmation(&snapshot, "WRONG-SERIAL-99", &dev.stable_id);
        assert!(matches!(wrong_serial, Err(SafetyError::ConfirmationFailed { .. })));

        // Wrong target ID fails closed
        let wrong_id = SafetyGate::verify_user_confirmation(&snapshot, "4C530001230415116032", "disk-other-99");
        assert!(matches!(wrong_id, Err(SafetyError::IdentityMismatch { .. })));
    }

    #[test]
    fn test_preflight_fails_when_device_disappears() {
        let dev = make_valid_disposable_target();
        let snapshot = ExecutionTargetSnapshot::from_device(&dev);

        let preflight = SafetyGate::preflight_revalidate(&snapshot, None);
        assert!(matches!(preflight, Err(SafetyError::DeviceDisappeared(_))));
    }

    #[test]
    fn test_preflight_fails_when_path_changes() {
        let dev = make_valid_disposable_target();
        let snapshot = ExecutionTargetSnapshot::from_device(&dev);

        let mut live = dev.clone();
        live.path = "/dev/sdc".to_string(); // Reconnected on different device letter

        let preflight = SafetyGate::preflight_revalidate(&snapshot, Some(&live));
        assert!(matches!(preflight, Err(SafetyError::PathMismatch { .. })));
    }

    #[test]
    fn test_preflight_fails_when_serial_changes() {
        let dev = make_valid_disposable_target();
        let snapshot = ExecutionTargetSnapshot::from_device(&dev);

        let mut live = dev.clone();
        live.serial = "TAMPERED-SERIAL-00".to_string();

        let preflight = SafetyGate::preflight_revalidate(&snapshot, Some(&live));
        assert!(matches!(preflight, Err(SafetyError::IdentityMismatch { .. })));
    }

    #[test]
    fn test_preflight_fails_when_capacity_changes() {
        let dev = make_valid_disposable_target();
        let snapshot = ExecutionTargetSnapshot::from_device(&dev);

        let mut live = dev.clone();
        live.capacity_bytes = 32_000_000_000; // Capacity anomaly

        let preflight = SafetyGate::preflight_revalidate(&snapshot, Some(&live));
        assert!(matches!(preflight, Err(SafetyError::CapacityMismatch { .. })));
    }

    #[test]
    fn test_preflight_fails_when_device_becomes_mounted() {
        let dev = make_valid_disposable_target();
        let snapshot = ExecutionTargetSnapshot::from_device(&dev);

        let mut live = dev.clone();
        live.mounted = true;
        live.mount_points = vec!["/mnt/data".to_string()];

        let preflight = SafetyGate::preflight_revalidate(&snapshot, Some(&live));
        assert!(matches!(preflight, Err(SafetyError::DeviceMounted(_, _))));
    }
}
