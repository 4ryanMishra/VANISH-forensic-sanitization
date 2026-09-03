use crate::common::sanitization::SanitizationStandard;

pub struct PolicyRule {
    pub standard: SanitizationStandard,
    pub name: &'static str,
    pub description: &'static str,
    pub target_media_suitability: &'static str,
    pub requires_crypto_capable: bool,
    pub requires_nvme_sanitize: bool,
    pub default_pass_count: u32,
}

pub static STANDARD_RULES: &[PolicyRule] = &[
    PolicyRule {
        standard: SanitizationStandard::Nist80088Clear,
        name: "NIST SP 800-88 Rev 1 — Clear",
        description: "Logical overwrite of all user-addressable storage locations with standard data patterns (single pass).",
        target_media_suitability: "HDD, SATA SSD, NVMe SSD, USB Flash Media",
        requires_crypto_capable: false,
        requires_nvme_sanitize: false,
        default_pass_count: 1,
    },
    PolicyRule {
        standard: SanitizationStandard::Nist80088Purge,
        name: "NIST SP 800-88 Rev 1 — Purge",
        description: "Low-level controller sanitize/erase command executing physical NAND discharge or internal cryptographic key alteration.",
        target_media_suitability: "Enterprise NVMe SSD, SATA SSD with Secure Erase support",
        requires_crypto_capable: false,
        requires_nvme_sanitize: true,
        default_pass_count: 1,
    },
    PolicyRule {
        standard: SanitizationStandard::Dod522022M3Pass,
        name: "DoD 5220.22-M (3-Pass)",
        description: "Pass 1: Fixed character (0x00), Pass 2: Inverted complement (0xFF), Pass 3: Random byte stream + verification.",
        target_media_suitability: "Magnetic HDD, Removable Flash (Host overwrite)",
        requires_crypto_capable: false,
        requires_nvme_sanitize: false,
        default_pass_count: 3,
    },
    PolicyRule {
        standard: SanitizationStandard::Ieee2883Purge,
        name: "IEEE 2883-2022 — Purge",
        description: "Solid-state storage sanitize standard requiring complete key destruction or physical block erase across over-provisioned space.",
        target_media_suitability: "NVMe SSD, Enterprise Flash",
        requires_crypto_capable: false,
        requires_nvme_sanitize: true,
        default_pass_count: 1,
    },
    PolicyRule {
        standard: SanitizationStandard::SinglePassZero,
        name: "Single-Pass Zero Stream",
        description: "Sequential overwriting with uniform zeroes (0x00). Fast logical wipe.",
        target_media_suitability: "All media types (Virtual Disks, Lab USB)",
        requires_crypto_capable: false,
        requires_nvme_sanitize: false,
        default_pass_count: 1,
    },
    PolicyRule {
        standard: SanitizationStandard::SinglePassRandom,
        name: "Single-Pass Pseudo-Random",
        description: "Sequential overwriting with high-entropy cryptographic pseudo-random stream.",
        target_media_suitability: "All media types",
        requires_crypto_capable: false,
        requires_nvme_sanitize: false,
        default_pass_count: 1,
    },
];
