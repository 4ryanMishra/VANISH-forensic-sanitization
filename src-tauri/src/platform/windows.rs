use crate::common::device::{Device, DeviceCapability, InterfaceType, MediaType};
use crate::device::identity::DeviceIdentityEngine;
use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::process::Command;

pub struct WindowsStoragePlatform;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WindowsDiskRaw {
    pub number: Option<u32>,
    pub path: Option<String>,
    pub friendly_name: Option<String>,
    pub serial_number: Option<String>,
    pub bus_type: Option<String>,
    pub media_type: Option<String>,
    pub size: Option<u64>,
    pub logical_sector_size: Option<u32>,
    pub physical_sector_size: Option<u32>,
    pub is_system: Option<bool>,
    pub is_boot: Option<bool>,
    pub is_read_only: Option<bool>,
    #[serde(default)]
    pub partitions: Vec<WindowsPartitionRaw>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WindowsPartitionRaw {
    pub drive_letter: Option<String>,
}

impl WindowsStoragePlatform {
    pub fn new() -> Self {
        Self
    }

    /// Enumerate storage devices on Windows using native PowerShell Storage/CIM cmdlets
    pub fn enumerate_devices(&self) -> Result<Vec<Device>> {
        // Try Primary Storage Module (Get-Disk)
        if let Ok(disks) = Self::query_get_disk() {
            if !disks.is_empty() {
                return Ok(Self::convert_raw_disks(disks));
            }
        }

        // Fallback to WMI/CIM (Win32_DiskDrive)
        if let Ok(disks) = Self::query_wmi_disks() {
            if !disks.is_empty() {
                return Ok(Self::convert_raw_disks(disks));
            }
        }

        Ok(vec![])
    }

    /// Query Windows Storage Module using Get-Disk & Get-Partition
    fn query_get_disk() -> Result<Vec<WindowsDiskRaw>> {
        let script = r#"
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'
$disks = @(Get-Disk | ForEach-Object {
    $d = $_
    $partitions = @(Get-Partition -DiskNumber $d.Number | ForEach-Object {
        $p = $_
        $vol = if ($p.DriveLetter) { Get-Volume -DriveLetter $p.DriveLetter } else { $null }
        [PSCustomObject]@{
            PartitionNumber = $p.PartitionNumber
            DriveLetter = if ($p.DriveLetter) { "$($p.DriveLetter):" } else { $null }
            Size = $p.Size
            Type = "$($p.Type)"
            FileSystem = if ($vol) { "$($vol.FileSystem)" } else { $null }
            FileSystemLabel = if ($vol) { "$($vol.FileSystemLabel)" } else { $null }
        }
    })
    [PSCustomObject]@{
        Number = $d.Number
        Path = "\\.\PhysicalDrive$($d.Number)"
        FriendlyName = "$($d.FriendlyName)"
        SerialNumber = if ($d.SerialNumber) { "$($d.SerialNumber)".Trim() } else { "UNKNOWN" }
        BusType = "$($d.BusType)"
        MediaType = "$($d.MediaType)"
        Size = $d.Size
        AllocatedSize = $d.AllocatedSize
        LogicalSectorSize = if ($d.LogicalSectorSize) { $d.LogicalSectorSize } else { 512 }
        PhysicalSectorSize = if ($d.PhysicalSectorSize) { $d.PhysicalSectorSize } else { 512 }
        OperationalStatus = "$($d.OperationalStatus)"
        IsSystem = [bool]$d.IsSystem
        IsBoot = [bool]$d.IsBoot
        IsReadOnly = [bool]$d.IsReadOnly
        IsOffline = [bool]$d.IsOffline
        Partitions = $partitions
    }
})
ConvertTo-Json -InputObject $disks -Depth 5 -Compress
"#;
        let json_str = Self::exec_powershell_encoded(script)?;
        let disks: Vec<WindowsDiskRaw> = Self::deserialize_disks(&json_str)?;
        Ok(disks)
    }

    /// Fallback query via CIM/WMI Win32_DiskDrive
    fn query_wmi_disks() -> Result<Vec<WindowsDiskRaw>> {
        let script = r#"
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'
$disks = @(Get-CimInstance Win32_DiskDrive | ForEach-Object {
    $d = $_
    $idx = $d.Index
    $partitions = @(Get-CimInstance -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='$($d.DeviceID.Replace('\','\\'))'} WHERE AssocClass = Win32_DiskDriveToDiskPartition" | ForEach-Object {
        $part = $_
        $logicals = @(Get-CimInstance -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($part.DeviceID)'} WHERE AssocClass = Win32_LogicalDiskToPartition")
        $letter = if ($logicals.Count -gt 0) { $logicals[0].DeviceID } else { $null }
        [PSCustomObject]@{
            PartitionNumber = $part.Index
            DriveLetter = $letter
            Size = $part.Size
            Type = "$($part.Type)"
            FileSystem = $null
            FileSystemLabel = $null
        }
    })
    [PSCustomObject]@{
        Number = $idx
        Path = $d.DeviceID
        FriendlyName = "$($d.Model)"
        SerialNumber = if ($d.SerialNumber) { "$($d.SerialNumber)".Trim() } else { "UNKNOWN" }
        BusType = "$($d.InterfaceType)"
        MediaType = "$($d.MediaType)"
        Size = $d.Size
        AllocatedSize = $d.Size
        LogicalSectorSize = if ($d.BytesPerSector) { $d.BytesPerSector } else { 512 }
        PhysicalSectorSize = if ($d.BytesPerSector) { $d.BytesPerSector } else { 512 }
        OperationalStatus = "$($d.Status)"
        IsSystem = ($idx -eq 0)
        IsBoot = ($idx -eq 0)
        IsReadOnly = $false
        IsOffline = $false
        Partitions = $partitions
    }
})
ConvertTo-Json -InputObject $disks -Depth 5 -Compress
"#;
        let json_str = Self::exec_powershell_encoded(script)?;
        let disks: Vec<WindowsDiskRaw> = Self::deserialize_disks(&json_str)?;
        Ok(disks)
    }

    fn deserialize_disks(json_str: &str) -> Result<Vec<WindowsDiskRaw>> {
        let trimmed = json_str.trim();
        if trimmed.is_empty() {
            return Ok(vec![]);
        }
        if trimmed.starts_with('[') {
            let list: Vec<WindowsDiskRaw> = serde_json::from_str(trimmed)?;
            Ok(list)
        } else {
            let single: WindowsDiskRaw = serde_json::from_str(trimmed)?;
            Ok(vec![single])
        }
    }

    fn convert_raw_disks(raw_disks: Vec<WindowsDiskRaw>) -> Vec<Device> {
        let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        let mut devices = Vec::new();

        for raw in raw_disks {
            let disk_number = raw.number.unwrap_or(0);
            let path = raw.path.unwrap_or_else(|| format!(r"\\.\PhysicalDrive{}", disk_number));
            let model = raw.friendly_name.filter(|s| !s.trim().is_empty()).unwrap_or_else(|| format!("PhysicalDrive{}", disk_number));
            let serial = raw.serial_number.filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "UNKNOWN".to_string());
            let capacity_bytes = raw.size.unwrap_or(0);
            let logical_block_size = raw.logical_sector_size.unwrap_or(512);
            let physical_block_size = raw.physical_sector_size.unwrap_or(logical_block_size);

            let bus_type_upper = raw.bus_type.as_deref().unwrap_or("").to_uppercase();
            let model_upper = model.to_uppercase();
            let media_type_upper = raw.media_type.as_deref().unwrap_or("").to_uppercase();

            // Detect Interface
            let interface = if bus_type_upper.contains("USB") || model_upper.contains("USB") || model_upper.contains("SANDISK") || model_upper.contains("CRUZER") {
                InterfaceType::Usb
            } else if bus_type_upper.contains("NVME") || model_upper.contains("NVME") {
                InterfaceType::Nvme
            } else if bus_type_upper.contains("SATA") || bus_type_upper.contains("ATA") || bus_type_upper.contains("IDE") {
                InterfaceType::Sata
            } else if bus_type_upper.contains("SCSI") || bus_type_upper.contains("SAS") || bus_type_upper.contains("RAID") {
                if model_upper.contains("NVME") {
                    InterfaceType::Nvme
                } else if model_upper.contains("USB") {
                    InterfaceType::Usb
                } else {
                    InterfaceType::Scsi
                }
            } else if bus_type_upper.contains("MMC") || bus_type_upper.contains("SD") {
                InterfaceType::Mmc
            } else if bus_type_upper.contains("VIRTUAL") || bus_type_upper.contains("FILE") {
                InterfaceType::Virtual
            } else {
                InterfaceType::Unknown(raw.bus_type.unwrap_or_default())
            };

            // Detect MediaType
            let media_type = match &interface {
                InterfaceType::Usb => MediaType::UsbFlash,
                InterfaceType::Nvme => MediaType::SsdNvme,
                InterfaceType::Mmc => MediaType::SdCard,
                InterfaceType::Virtual => MediaType::VirtualDisk,
                _ => {
                    if media_type_upper.contains("REMOVABLE") || media_type_upper.contains("USB") {
                        MediaType::UsbFlash
                    } else if media_type_upper.contains("SSD") || media_type_upper.contains("SOLID STATE") {
                        if interface == InterfaceType::Nvme || model_upper.contains("NVME") {
                            MediaType::SsdNvme
                        } else {
                            MediaType::SsdSata
                        }
                    } else if media_type_upper.contains("HDD") || media_type_upper.contains("HARD DISK") || media_type_upper.contains("FIXED") {
                        MediaType::Hdd
                    } else {
                        MediaType::Unknown(raw.media_type.unwrap_or_default())
                    }
                }
            };

            // Mount points and Drive letters
            let mut mount_points = Vec::new();
            for part in &raw.partitions {
                if let Some(letter) = &part.drive_letter {
                    let trimmed = letter.trim().to_uppercase();
                    if !trimmed.is_empty() && !mount_points.contains(&trimmed) {
                        mount_points.push(trimmed);
                    }
                }
            }

            let mounted = !mount_points.is_empty();

            // System Disk and Boot Device detection
            let has_system_drive_partition = mount_points.iter().any(|m| {
                m.eq_ignore_ascii_case(&system_drive)
                    || m.eq_ignore_ascii_case(&format!("{}:", system_drive.trim_end_matches(':')))
                    || m.eq_ignore_ascii_case("C:")
            });

            let is_system = raw.is_system.unwrap_or(false)
                || (disk_number == 0 && (raw.is_system == Some(true) || raw.is_boot == Some(true)))
                || has_system_drive_partition;

            let is_boot = raw.is_boot.unwrap_or(false) || is_system || has_system_drive_partition;

            let read_only = raw.is_read_only.unwrap_or(false);

            // Capabilities
            let mut capabilities = vec![DeviceCapability::HostBlockOverwrite];
            if interface == InterfaceType::Nvme {
                capabilities.push(DeviceCapability::NvmeSanitizeBlockErase);
                capabilities.push(DeviceCapability::NvmeSanitizeCryptoErase);
                capabilities.push(DeviceCapability::NvmeSanitizeOverwrite);
                capabilities.push(DeviceCapability::NvmeFormatCryptoErase);
                capabilities.push(DeviceCapability::NvmeFormatUserErase);
                capabilities.push(DeviceCapability::TrimSupported);
            }

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

            devices.push(Device {
                stable_id,
                path,
                model,
                serial,
                capacity_bytes,
                logical_block_size,
                physical_block_size,
                interface,
                media_type,
                mounted,
                mount_points,
                boot_device: is_boot,
                system_disk: is_system,
                read_only,
                is_simulated: false,
                capabilities,
            });
        }

        devices
    }

    /// Execute PowerShell script with Base64 encoding to prevent quote escaping corruption
    fn exec_powershell_encoded(script: &str) -> Result<String> {
        let utf16_bytes: Vec<u8> = script
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let encoded = Self::encode_base64(&utf16_bytes);

        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                &encoded,
            ])
            .output()
            .map_err(|e| anyhow!("Failed to execute powershell.exe: {}", e))?;

        if !output.status.success() {
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("PowerShell execution returned non-zero: {}", stderr_str));
        }

        let stdout_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(stdout_str)
    }

    fn encode_base64(bytes: &[u8]) -> String {
        const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0];
            let b1 = chunk.get(1).copied().unwrap_or(0);
            let b2 = chunk.get(2).copied().unwrap_or(0);

            out.push(CHARSET[(b0 >> 2) as usize] as char);
            out.push(CHARSET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);

            if chunk.len() > 1 {
                out.push(CHARSET[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
            } else {
                out.push('=');
            }

            if chunk.len() > 2 {
                out.push(CHARSET[(b2 & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    /// Check if a given drive letter or physical disk contains the active Windows System directory (C:\Windows)
    pub fn is_windows_system_disk(drive_path: &str) -> bool {
        let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        drive_path.starts_with(&system_drive) || drive_path.contains("PhysicalDrive0")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_convert_real_disks() {
        let raw_json = r#"[
            {
                "Number": 0,
                "Path": "\\\\.\\PhysicalDrive0",
                "FriendlyName": "NVMe INTEL SSDPEKNU512GZ",
                "SerialNumber": "E823_8FA6_BF53_0001",
                "BusType": "NVMe",
                "MediaType": "SSD",
                "Size": 512110190592,
                "LogicalSectorSize": 512,
                "PhysicalSectorSize": 512,
                "IsSystem": true,
                "IsBoot": true,
                "IsReadOnly": false,
                "Partitions": [
                    { "DriveLetter": "C:" }
                ]
            },
            {
                "Number": 1,
                "Path": "\\\\.\\PhysicalDrive1",
                "FriendlyName": "SanDisk Cruzer Blade",
                "SerialNumber": "4C530001210704113003",
                "BusType": "USB",
                "MediaType": "Removable",
                "Size": 15664676864,
                "LogicalSectorSize": 512,
                "PhysicalSectorSize": 512,
                "IsSystem": false,
                "IsBoot": false,
                "IsReadOnly": false,
                "Partitions": [
                    { "DriveLetter": "E:" }
                ]
            }
        ]"#;

        let raw_disks: Vec<WindowsDiskRaw> = serde_json::from_str(raw_json).unwrap();
        let devices = WindowsStoragePlatform::convert_raw_disks(raw_disks);

        assert_eq!(devices.len(), 2);

        // Disk 0 Check: System Disk Protected
        let disk0 = &devices[0];
        assert_eq!(disk0.path, r"\\.\PhysicalDrive0");
        assert_eq!(disk0.model, "NVMe INTEL SSDPEKNU512GZ");
        assert_eq!(disk0.interface, InterfaceType::Nvme);
        assert_eq!(disk0.media_type, MediaType::SsdNvme);
        assert!(disk0.system_disk, "Disk 0 must be flagged as system disk");
        assert!(disk0.boot_device, "Disk 0 must be flagged as boot device");
        assert!(!disk0.is_simulated);

        // Disk 1 Check: Real SanDisk USB Flash
        let disk1 = &devices[1];
        assert_eq!(disk1.path, r"\\.\PhysicalDrive1");
        assert_eq!(disk1.model, "SanDisk Cruzer Blade");
        assert_eq!(disk1.serial, "4C530001210704113003");
        assert_eq!(disk1.capacity_bytes, 15664676864);
        assert_eq!(disk1.interface, InterfaceType::Usb);
        assert_eq!(disk1.media_type, MediaType::UsbFlash);
        assert!(!disk1.system_disk, "Disk 1 is USB and must NOT be flagged as system disk");
        assert!(!disk1.boot_device, "Disk 1 is USB and must NOT be flagged as boot device");
        assert!(disk1.mounted);
        assert_eq!(disk1.mount_points, vec!["E:"]);
        assert!(!disk1.is_simulated);
    }

    #[test]
    fn test_base64_encoder() {
        let input = b"Hello, Windows Storage!";
        let encoded = WindowsStoragePlatform::encode_base64(input);
        assert_eq!(encoded, "SGVsbG8sIFdpbmRvd3MgU3RvcmFnZSE=");
    }

    #[test]
    fn test_live_windows_enumerate_devices() {
        let platform = WindowsStoragePlatform::new();
        let devices = platform.enumerate_devices().expect("Live enumeration should not error");
        println!("Live enumerated {} devices:", devices.len());
        for dev in &devices {
            println!("- Path: {}, Model: {}, Serial: {}, Cap: {}, Sys: {}, Boot: {}, Mounts: {:?}",
                dev.path, dev.model, dev.serial, dev.capacity_bytes, dev.system_disk, dev.boot_device, dev.mount_points
            );
        }
        assert!(!devices.is_empty(), "Expected at least 1 disk (system disk) on host Windows machine");
        let sys_disk = devices.iter().find(|d| d.system_disk);
        assert!(sys_disk.is_some(), "Expected host system disk to be identified and protected");
        let sys = sys_disk.unwrap();
        assert!(sys.system_disk);
        assert!(sys.boot_device);
        assert!(sys.mount_points.contains(&"C:".to_string()));
    }
}
