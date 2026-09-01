#[cfg(test)]
mod tests {
    use vanish_lib::common::device::{DeviceCapability, InterfaceType, MediaType};
    use vanish_lib::device::{CapabilityDiscoveryEngine, DeviceDiscoveryService, DeviceIdentityEngine};

    #[test]
    fn test_device_discovery_enumeration() {
        let discovery = DeviceDiscoveryService::new();
        let devices = discovery.list_devices().expect("enumeration should succeed");
        assert!(!devices.is_empty());

        let sandisk = devices.iter().find(|d| d.serial == "4C530001230415116032");
        assert!(sandisk.is_some(), "SanDisk USB lab media fixture must be discovered");
        let sandisk_dev = sandisk.unwrap();
        assert_eq!(sandisk_dev.media_type, MediaType::UsbFlash);
        assert!(!sandisk_dev.system_disk);
        assert!(sandisk_dev.capabilities.contains(&DeviceCapability::HostBlockOverwrite));
        assert!(!sandisk_dev.capabilities.contains(&DeviceCapability::NvmeSanitizeBlockErase));
    }

    #[test]
    fn test_stable_identity_reproducibility() {
        let id_a = DeviceIdentityEngine::compute_stable_id("SER123", "MODEL-A", "Usb", 16000000000);
        let id_b = DeviceIdentityEngine::compute_stable_id("SER123", "MODEL-A", "Usb", 16000000000);
        assert_eq!(id_a, id_b);
        assert!(id_a.starts_with("dev-"));
    }

    #[test]
    fn test_simulated_nvme_capabilities() {
        let discovery = DeviceDiscoveryService::new();
        let devices = discovery.list_devices().unwrap();
        let sim_nvme = devices.iter().find(|d| d.serial == "SIM-NVME-PURGE-9912").unwrap();

        assert_eq!(sim_nvme.media_type, MediaType::SsdNvme);
        assert!(sim_nvme.capabilities.contains(&DeviceCapability::NvmeSanitizeCryptoErase));
        assert!(sim_nvme.capabilities.contains(&DeviceCapability::NvmeSanitizeBlockErase));
    }
}
