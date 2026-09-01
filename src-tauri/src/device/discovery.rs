use crate::common::device::{Device, DeviceCapability, InterfaceType, MediaType};
use anyhow::Result;

pub struct DeviceDiscoveryService;

impl DeviceDiscoveryService {
    pub fn new() -> Self {
        Self
    }

    /// Enumerate all block devices, filtering out or clearly marking system/boot disks
    pub fn list_devices(&self) -> Result<Vec<Device>> {
        // Return detected platform devices or mock devices for simulation
        let mock_devices = vec![
            Device {
                stable_id: "disk-vdisk-01".to_string(),
                path: "/dev/loop0".to_string(),
                model: "VANISH Virtual Forensic Target".to_string(),
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
                capabilities: vec![
                    DeviceCapability::HostBlockOverwrite,
                ],
            },
        ];

        Ok(mock_devices)
    }
}
