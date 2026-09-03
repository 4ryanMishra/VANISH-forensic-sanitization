use crate::common::device::{Device, DeviceCapability, InterfaceType, MediaType};
use anyhow::Result;

pub struct MockPlatformStorage;

impl MockPlatformStorage {
    pub fn new() -> Self {
        Self
    }

    /// Returns high-fidelity laboratory test fixtures:
    /// 1. Physical 16 GB SanDisk USB flash drive (Host sequential write only)
    /// 2. Simulated 512 GB Enterprise NVMe SSD (Exposes real NVMe Sanitize / Crypto Erase capability flags for simulation)
    /// 3. Simulated 512 MB Virtual Forensic Disk Image (For reproducible read-only carving and zeroing tests)
    /// 4. Host System Disk (Explicitly marked as boot/system drive for safety gate validation)
    pub fn enumerate_mock_devices(&self) -> Result<Vec<Device>> {
        let fixtures = vec![
            Device {
                stable_id: "disk-sandisk-16g".to_string(),
                path: "/dev/sdb".to_string(),
                model: "SanDisk Ultra USB 3.0 (Physical Lab Media)".to_string(),
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
                capabilities: vec![
                    DeviceCapability::HostBlockOverwrite,
                    DeviceCapability::SmartHealthQuery,
                ],
            },
            Device {
                stable_id: "disk-sim-nvme-01".to_string(),
                path: "/dev/sim_nvme0n1".to_string(),
                model: "[Simulated] Enterprise NVMe SSD 512GB".to_string(),
                serial: "SIM-NVME-PURGE-9912".to_string(),
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
                capabilities: vec![
                    DeviceCapability::NvmeSanitizeBlockErase,
                    DeviceCapability::NvmeSanitizeCryptoErase,
                    DeviceCapability::NvmeSanitizeOverwrite,
                    DeviceCapability::NvmeFormatCryptoErase,
                    DeviceCapability::NvmeFormatUserErase,
                    DeviceCapability::TrimSupported,
                    DeviceCapability::SmartHealthQuery,
                ],
            },
            Device {
                stable_id: "disk-vdisk-01".to_string(),
                path: "/dev/loop0".to_string(),
                model: "[Simulated] VANISH Virtual Forensic Image".to_string(),
                serial: "VN-LAB-8821".to_string(),
                capacity_bytes: 512 * 1024 * 1024,
                logical_block_size: 512,
                physical_block_size: 4096,
                interface: InterfaceType::Virtual,
                media_type: MediaType::VirtualDisk,
                mounted: false,
                mount_points: vec![],
                boot_device: false,
                system_disk: false,
                read_only: false,
                is_simulated: true,
                capabilities: vec![
                    DeviceCapability::HostBlockOverwrite,
                    DeviceCapability::TrimSupported,
                ],
            },
            Device {
                stable_id: "disk-host-sys".to_string(),
                path: "/dev/nvme0n1".to_string(),
                model: "Host Primary System Disk (Write-Locked)".to_string(),
                serial: "SYS-HOST-PROTECTED-01".to_string(),
                capacity_bytes: 1_000_204_886_016,
                logical_block_size: 512,
                physical_block_size: 512,
                interface: InterfaceType::Nvme,
                media_type: MediaType::SsdNvme,
                mounted: true,
                mount_points: vec!["/".to_string(), "/boot/efi".to_string()],
                boot_device: true,
                system_disk: true,
                read_only: false,
                is_simulated: false,
                capabilities: vec![
                    DeviceCapability::NvmeSanitizeBlockErase,
                    DeviceCapability::NvmeSanitizeCryptoErase,
                    DeviceCapability::TrimSupported,
                ],
            },
        ];

        Ok(fixtures)
    }
}
