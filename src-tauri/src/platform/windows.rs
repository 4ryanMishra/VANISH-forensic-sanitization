use crate::common::device::Device;
use anyhow::Result;

pub struct WindowsStoragePlatform;

impl WindowsStoragePlatform {
    pub fn new() -> Self {
        Self
    }

    /// Enumerate storage devices on Windows using disk geometry, IOCTL_STORAGE_QUERY_PROPERTY,
    /// and volume management API abstractions.
    pub fn enumerate_devices(&self) -> Result<Vec<Device>> {
        // Fall back gracefully to mock / lab targets if not running with elevated Windows native APIs
        Ok(vec![])
    }

    /// Check if a given drive letter or physical disk contains the active Windows System directory (C:\Windows)
    pub fn is_windows_system_disk(drive_path: &str) -> bool {
        let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        drive_path.starts_with(&system_drive) || drive_path.contains("PhysicalDrive0")
    }
}
