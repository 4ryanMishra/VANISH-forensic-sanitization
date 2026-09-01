use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MediaType {
    Hdd,
    SsdNvme,
    SsdSata,
    UsbFlash,
    SdCard,
    VirtualDisk,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InterfaceType {
    Nvme,
    Sata,
    Scsi,
    Usb,
    Mmc,
    Virtual,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceCapability {
    NvmeFormatCryptoErase,
    NvmeFormatUserErase,
    NvmeSanitizeBlockErase,
    NvmeSanitizeCryptoErase,
    NvmeSanitizeOverwrite,
    AtaSecureErase,
    AtaEnhancedSecureErase,
    AtaSanitizeCrypto,
    AtaSanitizeBlock,
    ScsiSanitize,
    HostBlockOverwrite,
    TrimSupported,
    ReadOnlySwitchPresent,
    SmartHealthQuery,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
    pub stable_id: String,
    pub path: String,
    pub model: String,
    pub serial: String,
    pub capacity_bytes: u64,
    pub logical_block_size: u32,
    pub physical_block_size: u32,
    pub interface: InterfaceType,
    pub media_type: MediaType,
    pub mounted: bool,
    pub mount_points: Vec<String>,
    pub boot_device: bool,
    pub system_disk: bool,
    pub read_only: bool,
    pub capabilities: Vec<DeviceCapability>,
}
