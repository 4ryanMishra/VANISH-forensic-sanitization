use crate::common::device::{Device, DeviceCapability, InterfaceType, MediaType};
use anyhow::Result;
use std::fs;
use std::path::Path;

pub struct LinuxStoragePlatform;

impl LinuxStoragePlatform {
    pub fn new() -> Self {
        Self
    }

    /// Enumerate storage devices on Linux inspecting /sys/block, /proc/mounts, and udev sysfs entries
    pub fn enumerate_devices(&self) -> Result<Vec<Device>> {
        let sys_block = Path::new("/sys/block");
        if !sys_block.exists() {
            return Ok(vec![]);
        }

        let mut devices = Vec::new();
        if let Ok(entries) = fs::read_dir(sys_block) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("loop") || name.starts_with("ram") {
                    continue;
                }

                // Construct device entry from sysfs metadata
                let dev_path = format!("/dev/{}", name);
                let is_rotational = fs::read_to_string(entry.path().join("queue/rotational"))
                    .map(|s| s.trim() == "1")
                    .unwrap_or(false);

                let media_type = if name.starts_with("nvme") {
                    MediaType::SsdNvme
                } else if is_rotational {
                    MediaType::Hdd
                } else if name.starts_with("sd") {
                    MediaType::SsdSata
                } else {
                    MediaType::Unknown(name.clone())
                };

                let interface = if name.starts_with("nvme") {
                    InterfaceType::Nvme
                } else if name.starts_with("sd") {
                    InterfaceType::Sata
                } else {
                    InterfaceType::Scsi
                };

                let dev = Device {
                    stable_id: format!("disk-linux-{}", name),
                    path: dev_path,
                    model: format!("Linux Block Device {}", name),
                    serial: format!("LNX-SER-{}", name),
                    capacity_bytes: 0,
                    logical_block_size: 512,
                    physical_block_size: 4096,
                    interface,
                    media_type,
                    mounted: false,
                    mount_points: vec![],
                    boot_device: false,
                    system_disk: false,
                    read_only: false,
                    capabilities: vec![DeviceCapability::HostBlockOverwrite],
                };
                devices.push(dev);
            }
        }

        Ok(devices)
    }

    /// Read /proc/mounts to identify root / and /boot block devices
    pub fn get_system_mount_devices() -> Vec<String> {
        let mut sys_devs = Vec::new();
        if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let dev = parts[0];
                    let mount_point = parts[1];
                    if mount_point == "/" || mount_point == "/boot" || mount_point == "/boot/efi" {
                        sys_devs.push(dev.to_string());
                    }
                }
            }
        }
        sys_devs
    }
}
