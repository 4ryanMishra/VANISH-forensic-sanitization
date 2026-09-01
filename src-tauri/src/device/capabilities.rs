use crate::common::device::{DeviceCapability, InterfaceType, MediaType};

pub struct CapabilityDiscoveryEngine;

impl CapabilityDiscoveryEngine {
    /// Discovers and filters valid hardware capabilities based on media type, interface, and controller responses.
    /// Strictly adheres to docs/05_AGENT_RULES.md ("do not invent device capabilities") and
    /// docs/08_PHYSICAL_LAB.md (generic USB flash is never falsely granted NVMe/ATA sanitize capabilities).
    pub fn evaluate_capabilities(
        media_type: &MediaType,
        interface: &InterfaceType,
        reported_capabilities: &[DeviceCapability],
    ) -> Vec<DeviceCapability> {
        let mut valid_caps = Vec::new();

        match (media_type, interface) {
            (MediaType::UsbFlash, InterfaceType::Usb) => {
                // USB flash drives expose host block overwrite primitives only.
                // Hardware-level NVMe/ATA Sanitize commands are explicitly rejected.
                valid_caps.push(DeviceCapability::HostBlockOverwrite);
                if reported_capabilities.contains(&DeviceCapability::ReadOnlySwitchPresent) {
                    valid_caps.push(DeviceCapability::ReadOnlySwitchPresent);
                }
                if reported_capabilities.contains(&DeviceCapability::SmartHealthQuery) {
                    valid_caps.push(DeviceCapability::SmartHealthQuery);
                }
            }
            (MediaType::SsdNvme, InterfaceType::Nvme) => {
                // Enterprise NVMe controllers support Format NVM, Sanitize (Block/Crypto), and Trim
                for cap in reported_capabilities {
                    match cap {
                        DeviceCapability::NvmeSanitizeBlockErase
                        | DeviceCapability::NvmeSanitizeCryptoErase
                        | DeviceCapability::NvmeSanitizeOverwrite
                        | DeviceCapability::NvmeFormatCryptoErase
                        | DeviceCapability::NvmeFormatUserErase
                        | DeviceCapability::TrimSupported
                        | DeviceCapability::SmartHealthQuery => {
                            valid_caps.push(cap.clone());
                        }
                        _ => {}
                    }
                }
                valid_caps.push(DeviceCapability::HostBlockOverwrite);
            }
            (MediaType::SsdSata, InterfaceType::Sata) | (MediaType::Hdd, InterfaceType::Sata) => {
                for cap in reported_capabilities {
                    match cap {
                        DeviceCapability::AtaSecureErase
                        | DeviceCapability::AtaEnhancedSecureErase
                        | DeviceCapability::AtaSanitizeBlock
                        | DeviceCapability::AtaSanitizeCrypto
                        | DeviceCapability::TrimSupported
                        | DeviceCapability::SmartHealthQuery => {
                            valid_caps.push(cap.clone());
                        }
                        _ => {}
                    }
                }
                valid_caps.push(DeviceCapability::HostBlockOverwrite);
            }
            (MediaType::VirtualDisk, _) => {
                valid_caps.push(DeviceCapability::HostBlockOverwrite);
                valid_caps.push(DeviceCapability::TrimSupported);
            }
            _ => {
                valid_caps.push(DeviceCapability::HostBlockOverwrite);
            }
        }

        valid_caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usb_flash_never_gets_nvme_sanitize_capabilities() {
        let fake_reported = vec![
            DeviceCapability::NvmeSanitizeCryptoErase,
            DeviceCapability::HostBlockOverwrite,
        ];
        let evaluated = CapabilityDiscoveryEngine::evaluate_capabilities(
            &MediaType::UsbFlash,
            &InterfaceType::Usb,
            &fake_reported,
        );

        assert!(evaluated.contains(&DeviceCapability::HostBlockOverwrite));
        assert!(!evaluated.contains(&DeviceCapability::NvmeSanitizeCryptoErase));
    }

    #[test]
    fn test_nvme_ssd_retains_valid_sanitize_capabilities() {
        let reported = vec![
            DeviceCapability::NvmeSanitizeBlockErase,
            DeviceCapability::NvmeSanitizeCryptoErase,
        ];
        let evaluated = CapabilityDiscoveryEngine::evaluate_capabilities(
            &MediaType::SsdNvme,
            &InterfaceType::Nvme,
            &reported,
        );

        assert!(evaluated.contains(&DeviceCapability::NvmeSanitizeBlockErase));
        assert!(evaluated.contains(&DeviceCapability::NvmeSanitizeCryptoErase));
        assert!(evaluated.contains(&DeviceCapability::HostBlockOverwrite));
    }
}
