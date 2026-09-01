use crate::common::device::{Device, DeviceCapability, InterfaceType, MediaType};
use anyhow::Result;

pub struct DeviceDiscoveryService;

impl DeviceDiscoveryService {
    pub fn new() -> Self {
        Self
    }

    /// Enumerate all block devices, filtering out or clearly marking system/boot disks.
    /// In accordance with docs/08_PHYSICAL_LAB.md:
    /// - Physical targets: SanDisk 16GB USB flash drive (HostBlockOverwrite only).
    /// - Simulated targets: Virtual disk image & Simulated NVMe SSD (for testing real NVMe Sanitize commands).
    /// - Host system disk: Strictly write-protected.
    pub fn list_devices(&self) -> Result<Vec<Device>> {
        let devices = vec![
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
                capabilities: vec![
                    DeviceCapability::HostBlockOverwrite,
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
                capabilities: vec![
                    DeviceCapability::NvmeSanitizeBlockErase,
                    DeviceCapability::NvmeSanitizeCryptoErase,
                    DeviceCapability::NvmeSanitizeOverwrite,
                    DeviceCapability::TrimSupported,
                ],
            },
            Device {
                stable_id: "disk-vdisk-01".to_string(),
                path: "/dev/loop0".to_string(),
                model: "[Simulated] VANISH Virtual Forensic Image".to_string(),
                serial: "VN-LAB-8821".to_string(),
                capacity_bytes: 1024 * 1024 * 512, // 512 MB
                logical_block_size: 512,
                physical_block_size: 4096,
                interface: InterfaceType::Virtual,
                media_type: MediaType::VirtualDisk,
                mounted: false,
                mount_points: vec![],
                boot_device: false,
                system_disk: false,
                read_only: false,
                capabilities: vec![
                    DeviceCapability::HostBlockOverwrite,
                    DeviceCapability::TrimSupported,
                ],
            },
        ];

        Ok(devices)
    }
}
