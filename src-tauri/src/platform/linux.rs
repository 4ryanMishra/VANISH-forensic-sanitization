use crate::common::device::{Device, DeviceCapability, InterfaceType, MediaType};
use crate::device::identity::DeviceIdentityEngine;
use anyhow::Result;
use std::fs;
use std::path::Path;

pub struct LinuxStoragePlatform;

impl LinuxStoragePlatform {
    pub fn new() -> Self {
        Self
    }

    /// Enumerate storage devices on Linux from actual /sys/block and /proc/mounts
    pub fn enumerate_devices(&self) -> Result<Vec<Device>> {
        Self::enumerate_from_paths(Path::new("/sys/block"), Path::new("/proc/mounts"))
    }

    /// Enumerate devices from configurable sysfs and mounts paths (enables robust unit testing with mock fixtures)
    pub fn enumerate_from_paths(sys_block: &Path, proc_mounts: &Path) -> Result<Vec<Device>> {
        if !sys_block.exists() {
            return Ok(vec![]);
        }

        let mounts = Self::parse_proc_mounts(proc_mounts);
        let mut devices = Vec::new();

        if let Ok(entries) = fs::read_dir(sys_block) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();

                // Skip pseudo/virtual devices
                if name.starts_with("loop")
                    || name.starts_with("ram")
                    || name.starts_with("zram")
                    || name.starts_with("dm-")
                {
                    continue;
                }

                let block_dir = entry.path();
                if let Some(device) = Self::probe_block_device(&block_dir, &name, &mounts) {
                    devices.push(device);
                }
            }
        }

        Ok(devices)
    }

    fn probe_block_device(
        block_dir: &Path,
        name: &str,
        mounts: &[(String, String)],
    ) -> Option<Device> {
        let dev_path = format!("/dev/{}", name);

        // 1. Capacity in bytes (size in 512-byte sectors)
        let size_sectors: u64 = fs::read_to_string(block_dir.join("size"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let capacity_bytes = size_sectors.saturating_mul(512);

        // 2. Block sizes
        let logical_block_size: u32 = fs::read_to_string(block_dir.join("queue/logical_block_size"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(512);

        let physical_block_size: u32 = fs::read_to_string(block_dir.join("queue/physical_block_size"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(logical_block_size);

        // 3. Rotational & Media Type & Interface
        let is_rotational = fs::read_to_string(block_dir.join("queue/rotational"))
            .map(|s| s.trim() == "1")
            .unwrap_or(false);

        let uevent_content = fs::read_to_string(block_dir.join("uevent")).unwrap_or_default();
        let device_link = fs::read_link(block_dir.join("device"))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let is_usb = device_link.contains("usb") || uevent_content.contains("DEVTYPE=usb");
        let is_nvme = name.starts_with("nvme") || device_link.contains("nvme");
        let is_mmc = name.starts_with("mmcblk") || device_link.contains("mmc");

        let interface = if is_nvme {
            InterfaceType::Nvme
        } else if is_usb {
            InterfaceType::Usb
        } else if is_mmc {
            InterfaceType::Mmc
        } else if name.starts_with("sd") {
            InterfaceType::Sata
        } else {
            InterfaceType::Unknown(name.to_string())
        };

        let media_type = if is_nvme {
            MediaType::SsdNvme
        } else if is_usb {
            MediaType::UsbFlash
        } else if is_mmc {
            MediaType::SdCard
        } else if is_rotational {
            MediaType::Hdd
        } else if name.starts_with("sd") {
            MediaType::SsdSata
        } else {
            MediaType::Unknown(name.to_string())
        };

        // 4. Model and Serial detection without fabrication
        let model = fs::read_to_string(block_dir.join("device/model"))
            .or_else(|_| fs::read_to_string(block_dir.join("device/name")))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                if is_nvme {
                    format!("NVMe Device {}", name)
                } else if is_usb {
                    format!("USB Storage {}", name)
                } else {
                    format!("Block Device {}", name)
                }
            });

        let serial = fs::read_to_string(block_dir.join("device/serial"))
            .or_else(|_| fs::read_to_string(block_dir.join("device/wwid")))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "UNKNOWN".to_string());

        // 5. Read-only status
        let read_only = fs::read_to_string(block_dir.join("ro"))
            .map(|s| s.trim() == "1")
            .unwrap_or(false);

        // 6. Mount and System Disk detection
        let mut dev_mount_points = Vec::new();
        let mut is_system = false;
        let mut is_boot = false;

        for (m_dev, m_point) in mounts {
            let is_match = m_dev == &dev_path
                || m_dev.starts_with(&format!("{}/", dev_path))
                || m_dev.starts_with(&format!("{}p", dev_path))
                || m_dev.starts_with(&format!("{}_", dev_path))
                || (dev_path.starts_with("/dev/sd") && m_dev.starts_with(&dev_path));

            if is_match {
                if !dev_mount_points.contains(m_point) {
                    dev_mount_points.push(m_point.clone());
                }
                if m_point == "/" || m_point == "/usr" {
                    is_system = true;
                    is_boot = true;
                } else if m_point == "/boot" || m_point == "/boot/efi" {
                    is_boot = true;
                }
            }
        }

        let mounted = !dev_mount_points.is_empty();

        // 7. Capability detection (only verified capabilities)
        let mut capabilities = vec![DeviceCapability::HostBlockOverwrite];

        // Check TRIM / Discard
        let discard_bytes: u64 = fs::read_to_string(block_dir.join("queue/discard_max_bytes"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        if discard_bytes > 0 {
            capabilities.push(DeviceCapability::TrimSupported);
        }

        // 8. Deterministic stable ID
        let interface_str = match &interface {
            InterfaceType::Nvme => "Nvme",
            InterfaceType::Sata => "Sata",
            InterfaceType::Usb => "Usb",
            InterfaceType::Scsi => "Scsi",
            InterfaceType::Mmc => "Mmc",
            InterfaceType::Virtual => "Virtual",
            InterfaceType::Unknown(s) => s.as_str(),
        };
        let stable_id = DeviceIdentityEngine::compute_stable_id(&serial, &model, interface_str, capacity_bytes);

        Some(Device {
            stable_id,
            path: dev_path,
            model,
            serial,
            capacity_bytes,
            logical_block_size,
            physical_block_size,
            interface,
            media_type,
            mounted,
            mount_points: dev_mount_points,
            boot_device: is_boot,
            system_disk: is_system,
            read_only,
            is_simulated: false,
            capabilities,
        })
    }

    /// Read and parse /proc/mounts into (dev_path, mount_point) pairs
    pub fn parse_proc_mounts(proc_mounts: &Path) -> Vec<(String, String)> {
        let mut list = Vec::new();
        if let Ok(content) = fs::read_to_string(proc_mounts) {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    list.push((parts[0].to_string(), parts[1].to_string()));
                }
            }
        }
        list
    }
}
