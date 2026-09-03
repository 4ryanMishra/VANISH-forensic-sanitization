#[cfg(test)]
mod tests {
    use std::io::Write;
    use tempfile::NamedTempFile;
    use vanish_lib::common::device::{Device, DeviceCapability, InterfaceType, MediaType};
    use vanish_lib::common::sanitization::{SanitizationMethod, SanitizationStandard};
    use vanish_lib::deletion::FileShredder;
    use vanish_lib::policy::PolicyEngine;
    use vanish_lib::sanitization::{
        NvmeAdminCommand, NvmeFormatSecureErase, NvmeSanitizeAction, OverwriteEngine,
        OverwritePatternType, SanitizationAdapter,
    };

    #[test]
    fn test_policy_recommends_nvme_crypto_erase_for_nvme_purge() {
        let policy = PolicyEngine::new();
        let nvme_dev = Device {
            stable_id: "dev-sim-nvme".to_string(),
            path: "/dev/sim_nvme0n1".to_string(),
            model: "Enterprise NVMe".to_string(),
            serial: "SIM-NVME-001".to_string(),
            capacity_bytes: 512_000_000_000,
            logical_block_size: 512,
            physical_block_size: 4096,
            interface: InterfaceType::Nvme,
            media_type: MediaType::SsdNvme,
            mounted: false,
            mount_points: vec![],
            boot_device: false,
            system_disk: false,
            read_only: false,
            is_simulated: true,
            capabilities: vec![DeviceCapability::NvmeSanitizeCryptoErase],
        };

        let plan = policy.recommend_plan(&nvme_dev, SanitizationStandard::Nist80088Purge);
        assert_eq!(plan.method, SanitizationMethod::NvmeSanitizeCryptoErase);
        assert!(plan.simulation_mode);
    }

    #[test]
    fn test_policy_recommends_host_overwrite_for_usb_flash() {
        let policy = PolicyEngine::new();
        let usb_dev = Device {
            stable_id: "dev-sandisk-16g".to_string(),
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
            is_simulated: false,
            capabilities: vec![DeviceCapability::HostBlockOverwrite],
        };

        let plan = policy.recommend_plan(&usb_dev, SanitizationStandard::Nist80088Clear);
        assert!(matches!(plan.method, SanitizationMethod::HostSequentialOverwrite { .. }));
        assert!(!plan.warnings.is_empty(), "Must warn about flash FTL spare area");
    }

    #[test]
    fn test_nvme_admin_command_builder() {
        let cmd = NvmeAdminCommand::build_sanitize_command(
            NvmeSanitizeAction::CryptoErase,
            false,
            false,
            0,
            0,
        );

        assert_eq!(cmd.opcode, 0x84);
        assert_eq!(cmd.cdw10 & 0x07, 0x04); // SANACT = 4 (Crypto Erase)

        let fmt_cmd = NvmeAdminCommand::build_format_nvm_command(
            1,
            NvmeFormatSecureErase::CryptographicErase,
            0,
        );
        assert_eq!(fmt_cmd.opcode, 0x80);
        assert_eq!((fmt_cmd.cdw10 >> 9) & 0x07, 0x02); // SES = 2 (Crypto Erase)
    }

    #[test]
    fn test_overwrite_engine_stream_progress() {
        let mut progress_count = 0;
        let result = OverwriteEngine::execute_stream(
            OverwritePatternType::Fixed(0x00),
            4096 * 10,
            4096,
            |_written, _total| {
                progress_count += 1;
            },
        );

        assert!(result.is_ok());
        assert_eq!(progress_count, 10);
    }

    #[test]
    fn test_sanitization_adapter_execution() {
        let usb_dev = Device {
            stable_id: "dev-sandisk-16g".to_string(),
            path: "/dev/sdb".to_string(),
            model: "SanDisk Ultra".to_string(),
            serial: "4C530001230415116032".to_string(),
            capacity_bytes: 1024 * 1024, // 1MB for unit test
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
        };

        let plan = PolicyEngine::new().recommend_plan(&usb_dev, SanitizationStandard::SinglePassZero);
        let summary = SanitizationAdapter::execute(&plan, &usb_dev, |_pct, _phase| {}).expect("execution should succeed");

        assert!(summary.success);
        assert_eq!(summary.passes_completed, 1);
    }

    #[test]
    fn test_file_shredder_destroys_file() {
        let mut tmp_file = NamedTempFile::new().unwrap();
        tmp_file.write_all(b"CONFIDENTIAL FORENSIC EVIDENCE DATA 12345").unwrap();
        let path = tmp_file.path().to_path_buf();

        assert!(path.exists());
        let shredded_bytes = FileShredder::shred_file(&path, 3).unwrap();
        assert!(shredded_bytes > 0);
        assert!(!path.exists(), "Shredded file must be removed from disk");
    }

    #[test]
    fn test_real_block_overwrite_on_temp_storage() {
        let mut tmp_file = NamedTempFile::new().unwrap();
        let initial_payload = vec![0xABu8; 64 * 1024]; // 64 KB
        tmp_file.write_all(&initial_payload).unwrap();
        tmp_file.flush().unwrap();
        let path = tmp_file.path().to_path_buf();

        // 1. Pass 1: Zero-fill block overwrite
        let mut progress_called = false;
        let written = OverwriteEngine::execute_block_overwrite(
            &path,
            OverwritePatternType::Fixed(0x00),
            64 * 1024,
            4096,
            |_written, _total| {
                progress_called = true;
            },
        ).expect("Block overwrite should succeed");

        assert_eq!(written, 64 * 1024);
        assert!(progress_called);

        // Verify contents are strictly 0x00
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents.len(), 64 * 1024);
        assert!(contents.iter().all(|&b| b == 0x00), "All bytes must be zeroed");

        // 2. Pass 2: Pseudo-random overwrite
        OverwriteEngine::execute_block_overwrite(
            &path,
            OverwritePatternType::PseudoRandom { seed: Some(42) },
            64 * 1024,
            4096,
            |_written, _total| {},
        ).expect("Random block overwrite should succeed");

        let random_contents = std::fs::read(&path).unwrap();
        assert_ne!(random_contents, contents);
        let has_non_zero = random_contents.iter().any(|&b| b != 0x00);
        assert!(has_non_zero, "Random pass must write varied bytes");
    }

    #[test]
    fn test_nvme_adapter_refuses_usb_flash_device() {
        use vanish_lib::device::ExecutionTargetSnapshot;
        use vanish_lib::sanitization::{DeviceSanitizationAdapter, NvmeSanitizeAdapter};

        let usb_dev = Device {
            stable_id: "dev-sandisk-16g".to_string(),
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
            is_simulated: false,
            capabilities: vec![DeviceCapability::HostBlockOverwrite],
        };

        let snapshot = ExecutionTargetSnapshot::from_device(&usb_dev);
        let plan = PolicyEngine::new().recommend_plan(&usb_dev, SanitizationStandard::Nist80088Purge);

        let adapter = NvmeSanitizeAdapter;
        assert!(!adapter.can_execute(&plan, &snapshot), "NvmeSanitizeAdapter must refuse USB flash snapshot");
    }

    #[test]
    fn test_nvme_adapter_unsupported_on_real_hardware_without_driver() {
        use vanish_lib::device::ExecutionTargetSnapshot;
        use vanish_lib::sanitization::{DeviceSanitizationAdapter, NvmeSanitizeAdapter};

        let real_nvme_dev = Device {
            stable_id: "dev-nvme-physical".to_string(),
            path: "/dev/nvme0n1".to_string(),
            model: "Samsung 980 Pro".to_string(),
            serial: "S5GXNF0R123456".to_string(),
            capacity_bytes: 1_000_000_000_000,
            logical_block_size: 512,
            physical_block_size: 512,
            interface: InterfaceType::Nvme,
            media_type: MediaType::SsdNvme,
            mounted: false,
            mount_points: vec![],
            boot_device: false,
            system_disk: false,
            read_only: false,
            is_simulated: false, // REAL hardware
            capabilities: vec![DeviceCapability::NvmeSanitizeCryptoErase],
        };

        let snapshot = ExecutionTargetSnapshot::from_device(&real_nvme_dev);
        let mut plan = PolicyEngine::new().recommend_plan(&real_nvme_dev, SanitizationStandard::Nist80088Purge);
        plan.simulation_mode = false;

        let adapter = NvmeSanitizeAdapter;
        let result = adapter.execute(&plan, &snapshot, &real_nvme_dev, &mut |_pct, _phase| {});
        assert!(result.is_err(), "Must return UNSUPPORTED error in real mode rather than pretending");
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("UNSUPPORTED HARDWARE PRIMITIVE") || err_msg.contains("Real NVMe hardware sanitize"));
    }
}
