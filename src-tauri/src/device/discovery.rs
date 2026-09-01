use crate::common::device::{Device, InterfaceType, MediaType};
use crate::device::capabilities::CapabilityDiscoveryEngine;
use crate::device::identity::DeviceIdentityEngine;
use crate::platform::MockPlatformStorage;
use anyhow::Result;

pub struct DeviceDiscoveryService {
    mock_platform: MockPlatformStorage,
}

impl DeviceDiscoveryService {
    pub fn new() -> Self {
        Self {
            mock_platform: MockPlatformStorage::new(),
        }
    }

    /// Enumerate all storage targets, computing stable hardware IDs, filtering reported capabilities,
    /// and tagging system/boot disks.
    pub fn list_devices(&self) -> Result<Vec<Device>> {
        let raw_devices = self.mock_platform.enumerate_mock_devices()?;
        let mut processed_devices = Vec::new();

        for mut dev in raw_devices {
            // Compute deterministic stable identity
            let interface_desc = match &dev.interface {
                InterfaceType::Nvme => "Nvme",
                InterfaceType::Sata => "Sata",
                InterfaceType::Usb => "Usb",
                InterfaceType::Scsi => "Scsi",
                InterfaceType::Mmc => "Mmc",
                InterfaceType::Virtual => "Virtual",
                InterfaceType::Unknown(s) => s.as_str(),
            };

            dev.stable_id = DeviceIdentityEngine::compute_stable_id(
                &dev.serial,
                &dev.model,
                interface_desc,
                dev.capacity_bytes,
            );

            // Filter capabilities to eliminate false claims on generic media (e.g. USB flash)
            dev.capabilities = CapabilityDiscoveryEngine::evaluate_capabilities(
                &dev.media_type,
                &dev.interface,
                &dev.capabilities,
            );

            processed_devices.push(dev);
        }

        Ok(processed_devices)
    }

    /// Retrieve a single device by stable_id
    pub fn get_device_by_id(&self, stable_id: &str) -> Result<Option<Device>> {
        let devices = self.list_devices()?;
        Ok(devices.into_iter().find(|d| d.stable_id == stable_id))
    }
}
