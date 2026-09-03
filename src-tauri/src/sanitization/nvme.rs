use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// NVMe Admin Command Opcodes (NVM Express Base Specification 2.0)
pub const NVME_ADMIN_FORMAT_NVM: u8 = 0x80;
pub const NVME_ADMIN_SANITIZE: u8 = 0x84;
pub const NVME_ADMIN_GET_LOG_PAGE: u8 = 0x02;
pub const NVME_LOG_PAGE_SANITIZE_STATUS: u8 = 0x81;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NvmeSanitizeAction {
    ExitFailureMode = 0x01,
    BlockErase = 0x02,
    Overwrite = 0x03,
    CryptoErase = 0x04,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NvmeFormatSecureErase {
    NoErase = 0x00,
    UserDataErase = 0x01,
    CryptographicErase = 0x02,
}

/// 64-byte NVMe Submission Queue Entry (SQE) Command Structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeAdminCommand {
    pub opcode: u8,
    pub flags: u8,
    pub command_id: u16,
    pub nsid: u32,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

impl NvmeAdminCommand {
    /// Builds a genuine NVMe Sanitize Admin Command (Opcode 0x84)
    pub fn build_sanitize_command(
        action: NvmeSanitizeAction,
        no_deallocate: bool,
        invert_overwrite: bool,
        overwrite_pass_count: u8,
        overwrite_pattern: u32,
    ) -> Self {
        let mut cdw10: u32 = action as u32 & 0x07;
        if no_deallocate {
            cdw10 |= 1 << 9;
        }
        if invert_overwrite && action == NvmeSanitizeAction::Overwrite {
            cdw10 |= 1 << 7;
        }
        if action == NvmeSanitizeAction::Overwrite {
            cdw10 |= ((overwrite_pass_count.min(16) as u32) & 0x0F) << 4;
        }

        Self {
            opcode: NVME_ADMIN_SANITIZE,
            flags: 0x00,
            command_id: 0x0001,
            nsid: 0x00000000, // 0 for controller-wide sanitize
            cdw10,
            cdw11: overwrite_pattern,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    /// Builds a genuine NVMe Format NVM Admin Command (Opcode 0x80)
    pub fn build_format_nvm_command(
        nsid: u32,
        ses: NvmeFormatSecureErase,
        lbaf: u8,
    ) -> Self {
        // CDW10: bits 11:9 = SES (Secure Erase Settings), bits 3:0 = LBAF
        let cdw10 = ((ses as u32 & 0x07) << 9) | (lbaf as u32 & 0x0F);

        Self {
            opcode: NVME_ADMIN_FORMAT_NVM,
            flags: 0x00,
            command_id: 0x0002,
            nsid,
            cdw10,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }
}

/// Parsed NVMe Sanitize Status Log Page (Log ID 0x81, 512 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvmeSanitizeStatusLog {
    pub progress_percentage: f32, // Computed from SPROG (0..65535)
    pub status_code: u16,         // Bits 2:0 of SSTAT (0=Never sanitized, 1=Success, 2=In-progress, 3=Failed)
    pub global_data_erased: bool, // Bit 8 of SSTAT
    pub status_description: String,
}

impl NvmeSanitizeStatusLog {
    pub fn parse(raw_512_bytes: &[u8]) -> Result<Self> {
        if raw_512_bytes.len() < 8 {
            return Err(anyhow!("Invalid Sanitize Status Log page size: minimum 8 bytes required"));
        }

        let sprog = u16::from_le_bytes([raw_512_bytes[0], raw_512_bytes[1]]);
        let sstat = u16::from_le_bytes([raw_512_bytes[2], raw_512_bytes[3]]);

        let progress_percentage = if sprog == 0xFFFF || sprog == 0 {
            if (sstat & 0x07) == 1 { 100.0 } else { 0.0 }
        } else {
            ((sprog as f32) / 65535.0) * 100.0
        };

        let status_code = sstat & 0x07;
        let global_data_erased = (sstat & (1 << 8)) != 0;

        let status_description = match status_code {
            0 => "Sanitize operation never executed on controller".to_string(),
            1 => "Most recent sanitize operation completed successfully".to_string(),
            2 => "Sanitize operation currently in progress".to_string(),
            3 => "Sanitize operation failed".to_string(),
            _ => format!("Unknown sanitize controller status code: {}", status_code),
        };

        Ok(Self {
            progress_percentage,
            status_code,
            global_data_erased,
            status_description,
        })
    }
}

/// Simulated NVMe Controller Executor (Validates command structures on simulation fixture disk-sim-nvme-01)
pub struct SimulatedNvmeController;

impl SimulatedNvmeController {
    pub fn execute_sanitize_simulation(
        cmd: &NvmeAdminCommand,
        mut progress_cb: impl FnMut(f32, &str),
    ) -> Result<NvmeSanitizeStatusLog> {
        if cmd.opcode != NVME_ADMIN_SANITIZE {
            return Err(anyhow!("Invalid opcode for sanitize simulation: 0x{:02X}", cmd.opcode));
        }

        let action_code = cmd.cdw10 & 0x07;
        let action_desc = match action_code {
            0x02 => "NVMe Block Erase (Discharging physical flash cells across all NAND channels)",
            0x04 => "NVMe Crypto Erase (Purging internal controller master encryption key MEK)",
            0x03 => "NVMe Overwrite (Controller hardware pattern sequencer active)",
            _ => "NVMe Custom Sanitize Action",
        };

        // Step-by-step progress simulation
        for pct in [10.0, 35.0, 70.0, 95.0, 100.0] {
            progress_cb(pct, action_desc);
        }

        Ok(NvmeSanitizeStatusLog {
            progress_percentage: 100.0,
            status_code: 1,
            global_data_erased: true,
            status_description: format!("Simulated {} completed with Global Data Erased flag verified.", action_desc),
        })
    }
}
