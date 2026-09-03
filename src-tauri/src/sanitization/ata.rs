use serde::{Deserialize, Serialize};

/// ATA Command Opcodes (ACS-4 / ACS-5 Specifications)
pub const ATA_CMD_SECURITY_ERASE_PREPARE: u8 = 0xF3;
pub const ATA_CMD_SECURITY_ERASE_UNIT: u8 = 0xF4;
pub const ATA_CMD_SANITIZE_DEVICE: u8 = 0xB4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtaSanitizeSubcommand {
    CryptoScramble = 0x0011,
    BlockErase = 0x0012,
    Overwrite = 0x0014,
    SanitizeFreeze = 0x0041,
    SanitizeStatus = 0x0040,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtaCommandFrame {
    pub command: u8,
    pub feature: u16,
    pub count: u16,
    pub lba: u64,
    pub device: u8,
}

impl AtaCommandFrame {
    /// Builds an ATA SANITIZE DEVICE command frame
    pub fn build_sanitize_frame(subcommand: AtaSanitizeSubcommand) -> Self {
        Self {
            command: ATA_CMD_SANITIZE_DEVICE,
            feature: subcommand as u16,
            count: 0,
            lba: 0,
            device: 0x40, // LBA mode
        }
    }

    /// Builds an ATA SECURITY ERASE UNIT command frame
    pub fn build_security_erase_frame(enhanced: bool) -> Self {
        Self {
            command: ATA_CMD_SECURITY_ERASE_UNIT,
            feature: if enhanced { 0x0001 } else { 0x0000 },
            count: 0,
            lba: 0,
            device: 0x40,
        }
    }
}
