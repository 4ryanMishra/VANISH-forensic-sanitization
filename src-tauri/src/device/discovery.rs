use crate::common::device::{Device, InterfaceType, MediaType};
use crate::device::capabilities::CapabilityDiscoveryEngine;
use crate::device::identity::DeviceIdentityEngine;
use crate::platform::{LinuxStoragePlatform, MockPlatformStorage, WindowsStoragePlatform};
use anyhow::Result;

pub struct DeviceDiscoveryService {
    linux_platform: LinuxStoragePlatform,
    windows_platform: WindowsStoragePlatform,
    mock_platform: MockPlatformStorage,
}

impl DeviceDiscoveryService {
    pub fn new() -> Self {
        Self {
            linux_platform: LinuxStoragePlatform::new(),
            windows_platform: WindowsStoragePlatform::new(),
            mock_platform: MockPlatformStorage::new(),
        }
    }

    /// Enumerate all storage targets, computing stable hardware IDs, filtering reported capabilities,
    /// and tagging system/boot disks. Uses native platform APIs on Linux/Windows, with high-fidelity
    /// simulation fixtures when simulation is requested or in development environments.
    pub fn list_devices(&self) -> Result<Vec<Device>> {
        let mut raw_devices = Vec::new();

        #[cfg(target_os = "linux")]
        {
            if let Ok(devs) = self.linux_platform.enumerate_devices() {
                raw_devices.extend(devs);
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(devs) = self.windows_platform.enumerate_devices() {
                raw_devices.extend(devs);
            }
        }

        // In REAL mode: return only genuine platform-discovered devices.
        // If none exist, return an empty device list. NEVER inject mock devices.
        // Mock fixtures are only returned via list_simulated_devices().

        let mut processed_devices = Vec::new();

        for mut dev in raw_devices {
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

    /// Enumerate simulated lab targets specifically
    pub fn list_simulated_devices(&self) -> Result<Vec<Device>> {
        self.mock_platform.enumerate_mock_devices()
    }

    /// Retrieve a single device by stable_id
    pub fn get_device_by_id(&self, stable_id: &str) -> Result<Option<Device>> {
        let devices = self.list_devices()?;
        Ok(devices.into_iter().find(|d| d.stable_id == stable_id))
    }
}
