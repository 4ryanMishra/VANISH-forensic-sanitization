use crate::common::device::{Device, DeviceCapability, MediaType};
use super::{
    pattern::{scan_pattern, ExpectedPattern},
    sampling::{
        analyse_entropy, generate_simulated_samples, EntropyVerdict, ExpectedEntropyMode,
    },
    types::{VerificationLevel, VerificationReport, VerificationResult, VerificationStatus},
};
use chrono::Utc;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

/// Input parameters for a verification run.
#[derive(Debug, Clone)]
pub struct VerificationRequest {
    /// The device that was sanitized.
    pub device: Device,
    /// Which levels to execute. Ordering is enforced: L1 → L2 → L3 → L4.
    pub levels_requested: Vec<VerificationLevel>,
    /// The sanitization method that was executed (determines expected entropy profile).
    pub sanitization_method: String,
    /// True when running in simulation mode (no physical block device).
    pub simulation_mode: bool,
}

pub struct VerificationEngine;

impl VerificationEngine {
    pub fn new() -> Self {
        Self
    }

    /// Run the full verification matrix and return an aggregated report.
    pub fn run(&self, req: &VerificationRequest) -> VerificationReport {
        let timestamp = Utc::now().to_rfc3339();
        let mut results: Vec<VerificationResult> = vec![];
        let mut unsupported: Vec<VerificationLevel> = vec![];

        // Determine expected entropy mode from sanitization method string
        let entropy_mode = if req.sanitization_method.contains("CryptoErase")
            || req.sanitization_method.contains("Crypto")
        {
            ExpectedEntropyMode::CryptoErase
        } else if req.sanitization_method.contains("Zero") {
            ExpectedEntropyMode::ZeroFill
        } else {
            ExpectedEntropyMode::RandomOverwrite
        };

        // Determine expected pattern from sanitization method
        let expected_pattern = match entropy_mode {
            ExpectedEntropyMode::ZeroFill => ExpectedPattern::Zero,
            _ => ExpectedPattern::Random,
        };

        // Execute each level in order
        let all_levels = [
            VerificationLevel::L1Logical,
            VerificationLevel::L2HostVisible,
            VerificationLevel::L3DeviceReported,
            VerificationLevel::L4Forensic,
        ];

        for level in &all_levels {
            if !req.levels_requested.contains(level) {
                continue;
            }

            let result = match level {
                VerificationLevel::L1Logical => {
                    self.run_l1_logical(&req.device, req.simulation_mode)
                }
                VerificationLevel::L2HostVisible => {
                    self.run_l2_host_visible(&req.device, &entropy_mode, &expected_pattern, req.simulation_mode)
                }
                VerificationLevel::L3DeviceReported => {
                    let result = self.run_l3_device_reported(&req.device, req.simulation_mode);
                    if result.status == VerificationStatus::Unsupported {
                        unsupported.push(level.clone());
                    }
                    result
                }
                VerificationLevel::L4Forensic => {
                    self.run_l4_forensic(&req.device, req.simulation_mode)
                }
            };

            results.push(result);
        }

        // Overall pass requires all executed non-Unsupported and non-NotAvailable levels to pass
        let overall_passed = results.iter().all(|r| {
            r.status == VerificationStatus::Pass
                || r.status == VerificationStatus::Unsupported
                || r.status == VerificationStatus::NotAvailable
        }) && results.iter().any(|r| r.status == VerificationStatus::Pass);

        let confidence_pct = compute_confidence_score(&results);

        VerificationReport {
            target_id: req.device.stable_id.clone(),
            levels_executed: results.iter().map(|r| r.level.clone()).collect(),
            results,
            overall_passed,
            confidence_pct,
            timestamp_utc: timestamp,
            unsupported_levels: unsupported,
            is_simulation: req.simulation_mode,
        }
    }

    // ── L1: Logical filesystem metadata ─────────────────────────────────────

    fn run_l1_logical(&self, device: &Device, simulation_mode: bool) -> VerificationResult {
        let timestamp = Utc::now().to_rfc3339();
        let mut evidence = vec![];
        let mut limitations = vec![];

        if simulation_mode {
            evidence.push(format!(
                "[SIMULATION] Partition table inspection: device '{}' returns blank MBR (all 0x00)",
                device.stable_id
            ));
            evidence.push("[SIMULATION] blkid: no filesystem signature detected on any partition".to_string());
            evidence.push("[SIMULATION] Directory root: no mountable filesystem found".to_string());

            limitations.push("Verified against simulated virtual state; no physical sector read issued.".to_string());

            VerificationResult {
                level: VerificationLevel::L1Logical,
                status: VerificationStatus::Pass,
                method: "Logical MBR/GPT Partition Inspection (Simulation)".to_string(),
                confidence_pct: 85,
                detail: format!(
                    "Logical verification PASSED (Simulation). Device '{}' exposes no active filesystem metadata.",
                    device.stable_id
                ),
                evidence,
                timestamp,
                limitations,
            }
        } else {
            // Physical disk sector 0 read
            let mut file = match File::open(&device.path) {
                Ok(f) => f,
                Err(e) => {
                    evidence.push(format!("Failed to open device '{}' for raw read: {}", device.path, e));
                    limitations.push("Insufficient privilege or device access to read physical sector 0.".to_string());

                    return VerificationResult {
                        level: VerificationLevel::L1Logical,
                        status: VerificationStatus::NotAvailable,
                        method: "Physical Sector 0 (MBR/GPT) Direct Inspection".to_string(),
                        confidence_pct: 0,
                        detail: format!("Logical verification NOT AVAILABLE: Cannot open '{}' for raw sector read.", device.path),
                        evidence,
                        timestamp,
                        limitations,
                    };
                }
            };

            let mut sector0 = [0u8; 512];
            if let Err(e) = file.read_exact(&mut sector0) {
                evidence.push(format!("Error reading sector 0: {}", e));
                limitations.push("I/O error reading physical boot sector.".to_string());

                return VerificationResult {
                    level: VerificationLevel::L1Logical,
                    status: VerificationStatus::NotAvailable,
                    method: "Physical Sector 0 (MBR/GPT) Direct Inspection".to_string(),
                    confidence_pct: 0,
                    detail: format!("Logical verification NOT AVAILABLE on '{}' due to read error.", device.path),
                    evidence,
                    timestamp,
                    limitations,
                };
            }

            let is_all_zero = sector0.iter().all(|&b| b == 0x00);
            let has_mbr_magic = sector0[510..512] == [0x55, 0xAA];

            evidence.push(format!("Sector 0 read from '{}' (512 bytes)", device.path));
            evidence.push(format!("Sector 0 all zeroes: {}", is_all_zero));
            evidence.push(format!("MBR boot signature (0x55AA) present: {}", has_mbr_magic));

            limitations.push("Only checks logical host-visible block 0; does not verify internal unmapped flash blocks.".to_string());

            if is_all_zero || !has_mbr_magic {
                VerificationResult {
                    level: VerificationLevel::L1Logical,
                    status: VerificationStatus::Pass,
                    method: "Physical Sector 0 (MBR/GPT) Direct Inspection".to_string(),
                    confidence_pct: 90,
                    detail: format!("Logical verification PASSED: Device '{}' contains no valid MBR/GPT partition tables.", device.path),
                    evidence,
                    timestamp,
                    limitations,
                }
            } else {
                VerificationResult {
                    level: VerificationLevel::L1Logical,
                    status: VerificationStatus::Fail,
                    method: "Physical Sector 0 (MBR/GPT) Direct Inspection".to_string(),
                    confidence_pct: 90,
                    detail: format!("Logical verification FAILED: Device '{}' still contains a valid MBR/partition table signature (0x55AA).", device.path),
                    evidence,
                    timestamp,
                    limitations,
                }
            }
        }
    }

    // ── L2: Host-visible block sampling ─────────────────────────────────────

    fn run_l2_host_visible(
        &self,
        device: &Device,
        entropy_mode: &ExpectedEntropyMode,
        expected_pattern: &ExpectedPattern,
        simulation_mode: bool,
    ) -> VerificationResult {
        let timestamp = Utc::now().to_rfc3339();
        let sample_count = 64;
        let block_size = (device.logical_block_size as u32).max(512);
        let mut limitations = vec![];
        let mut evidence = vec![];

        let (samples, is_simulated_sampling) = if simulation_mode {
            limitations.push("Entropy and pattern scan performed over simulated sample blocks.".to_string());
            (
                generate_simulated_samples(
                    device.capacity_bytes,
                    block_size,
                    sample_count,
                    entropy_mode,
                ),
                true,
            )
        } else {
            // Attempt to read physical sample blocks
            match File::open(&device.path) {
                Ok(mut file) => {
                    let total_blocks = (device.capacity_bytes / block_size as u64).max(1);
                    let stride = (total_blocks / sample_count as u64).max(1);
                    let mut real_samples = Vec::new();
                    let mut read_err = false;

                    for i in 0..sample_count {
                        let lba = (i as u64 * stride).min(total_blocks - 1);
                        let offset = lba * block_size as u64;

                        if file.seek(SeekFrom::Start(offset)).is_ok() {
                            let mut buf = vec![0u8; block_size as usize];
                            if file.read_exact(&mut buf).is_ok() {
                                real_samples.push(super::sampling::BlockSample {
                                    lba,
                                    data: buf,
                                });
                            } else {
                                read_err = true;
                                break;
                            }
                        } else {
                            read_err = true;
                            break;
                        }
                    }

                    if read_err || real_samples.is_empty() {
                        evidence.push(format!("Failed to sample physical LBAs from '{}'", device.path));
                        evidence.push("Direct physical LBA read error or permission denied.".to_string());
                        limitations.push("Insufficient privilege or device I/O error reading physical LBAs.".to_string());

                        return VerificationResult {
                            level: VerificationLevel::L2HostVisible,
                            status: VerificationStatus::NotAvailable,
                            method: format!("LBA Sampling & Shannon Entropy Analysis (Pattern: {:?})", expected_pattern),
                            confidence_pct: 0,
                            detail: format!("Host-visible verification NOT AVAILABLE on '{}' due to LBA read error.", device.path),
                            evidence,
                            timestamp,
                            limitations,
                        };
                    } else {
                        limitations.push("Scanned host-accessible addressable LBAs; out-of-band wear-leveling flash cells cannot be reached.".to_string());
                        (real_samples, false)
                    }
                }
                Err(e) => {
                    evidence.push(format!("Failed to open device '{}' for LBA sampling: {}", device.path, e));
                    evidence.push("OS error opening device handle for raw block read.".to_string());
                    limitations.push(format!("Device path unreadable: {}", e));

                    return VerificationResult {
                        level: VerificationLevel::L2HostVisible,
                        status: VerificationStatus::NotAvailable,
                        method: format!("LBA Sampling & Shannon Entropy Analysis (Pattern: {:?})", expected_pattern),
                        confidence_pct: 0,
                        detail: format!("Host-visible verification NOT AVAILABLE on '{}': cannot open path ({}).", device.path, e),
                        evidence,
                        timestamp,
                        limitations,
                    };
                }
            }
        };

        let entropy_analysis = analyse_entropy(&samples, entropy_mode);
        let sample_refs: Vec<(u64, &[u8])> = samples.iter().map(|s| (s.lba, s.data.as_slice())).collect();
        let pattern_result = scan_pattern(&sample_refs, expected_pattern);

        let sim_prefix = if is_simulated_sampling { "[SIMULATION] " } else { "" };

        evidence.push(format!(
            "{sim_prefix}Block samples analysed: {} across LBA space (stride: {})",
            samples.len(),
            device.capacity_bytes / block_size as u64 / sample_count as u64
        ));
        evidence.push(format!(
            "{sim_prefix}Shannon entropy metrics: mean={:.4} bits/byte, min={:.4}, max={:.4}",
            entropy_analysis.mean_entropy,
            entropy_analysis.min_entropy,
            entropy_analysis.max_entropy
        ));
        evidence.push(format!(
            "{sim_prefix}Pattern verification: {}/{} sampled blocks match expected pattern ({:?})",
            pattern_result.blocks_passed, pattern_result.blocks_checked, expected_pattern
        ));

        let entropy_ok = entropy_analysis.verdict != EntropyVerdict::AnomalousResidual
            && entropy_analysis.verdict != EntropyVerdict::NoSamples;
        let pattern_ok = pattern_result.overall_passed;

        let status = if entropy_ok && pattern_ok {
            VerificationStatus::Pass
        } else {
            VerificationStatus::Fail
        };

        let confidence = match (&entropy_analysis.verdict, pattern_ok) {
            (EntropyVerdict::CleanZeroFill, true) => 95u8,
            (EntropyVerdict::CleanHighEntropy, true) => 98,
            (EntropyVerdict::CleanRandomOverwrite, true) => 92,
            (EntropyVerdict::AnomalousResidual, _) => 20,
            _ => 60,
        };

        VerificationResult {
            level: VerificationLevel::L2HostVisible,
            status: status.clone(),
            method: format!("LBA Sampling & Shannon Entropy Analysis (Pattern: {:?})", expected_pattern),
            confidence_pct: confidence,
            detail: format!(
                "Host-visible verification {}: entropy verdict {:?}, pattern match {}. {} samples evaluated at block_size={}.",
                if status == VerificationStatus::Pass { "PASSED" } else { "FAILED" },
                entropy_analysis.verdict,
                if pattern_ok { "PASS" } else { "FAIL" },
                samples.len(),
                block_size,
            ),
            evidence,
            timestamp,
            limitations,
        }
    }

    // ── L3: Device-reported (NVMe Sanitize Status Log) ──────────────────────

    fn run_l3_device_reported(&self, device: &Device, simulation_mode: bool) -> VerificationResult {
        let timestamp = Utc::now().to_rfc3339();

        // Check if media is NVMe
        let is_nvme = matches!(device.media_type, MediaType::SsdNvme)
            || device.capabilities.iter().any(|c| matches!(
                c,
                DeviceCapability::NvmeSanitizeBlockErase
                    | DeviceCapability::NvmeSanitizeCryptoErase
                    | DeviceCapability::NvmeSanitizeOverwrite
            ));

        if !is_nvme {
            return VerificationResult {
                level: VerificationLevel::L3DeviceReported,
                status: VerificationStatus::Unsupported,
                method: "NVMe Sanitize Status Log (Log Page 0x81)".to_string(),
                confidence_pct: 0,
                detail: format!(
                    "L3 Device-Reported verification is UNSUPPORTED for media type '{:?}' on device '{}'. \
                     Device-level sanitize log telemetry is architecturally exclusive to native NVMe 1.3+ SSDs.",
                    device.media_type, device.stable_id
                ),
                evidence: vec![
                    format!("Device interface: {:?}", device.interface),
                    format!("Media type: {:?}", device.media_type),
                    "Hardware Sanitize Status Log (0x81) not supported on USB / SATA / virtual storage buses.".to_string(),
                ],
                timestamp,
                limitations: vec![
                    "USB mass storage and SATA bridges do not implement NVMe Sanitize Log Page 0x81.".to_string(),
                ],
            };
        }

        // On real hardware NVMe where physical kernel ioctl driver is unavailable, do NOT fabricate values
        if !simulation_mode {
            return VerificationResult {
                level: VerificationLevel::L3DeviceReported,
                status: VerificationStatus::NotAvailable,
                method: "NVMe Sanitize Status Log (Log Page 0x81)".to_string(),
                confidence_pct: 0,
                detail: format!(
                    "L3 Device-Reported verification is NOT AVAILABLE on '{}'. Real physical NVMe admin command ioctl (0x02) requires root kernel driver privileges.",
                    device.stable_id
                ),
                evidence: vec![
                    "NVME_IOCTL_ADMIN_CMD passthrough unavailable without elevated kernel driver access.".to_string(),
                    "No synthetic status values generated to ensure verification veracity.".to_string(),
                ],
                timestamp,
                limitations: vec![
                    "Requires root kernel NVMe driver access to query Log Page 0x81 via ioctl.".to_string(),
                ],
            };
        }

        // Simulation Mode NVMe Log
        let mut evidence = vec![];
        let sstat: u8 = 0x01; // Sanitize Successful
        let sprog: u16 = 0xFFFF; // 100% progress
        let global_data_erased = true;

        evidence.push(format!("[SIMULATION] NVMe Log Page 0x81 (Sanitize Status) read for '{}'", device.stable_id));
        evidence.push(format!("[SIMULATION] SSTAT[2:0] = 0x{sstat:02X} → Sanitize Successful"));
        evidence.push(format!("[SIMULATION] SPROG = 0x{sprog:04X} = {:.1}% complete", (sprog as f32 / 65535.0) * 100.0));
        evidence.push(format!("[SIMULATION] Global Data Erased bit = {global_data_erased}"));

        VerificationResult {
            level: VerificationLevel::L3DeviceReported,
            status: VerificationStatus::Pass,
            method: "NVMe Sanitize Status Log (Simulation)".to_string(),
            confidence_pct: 85,
            detail: format!(
                "NVMe Sanitize Status Log PASSED (Simulation): SSTAT=0x01 (Successful), SPROG=0xFFFF (100%), GlobalDataErased=true on device '{}'.",
                device.stable_id
            ),
            evidence,
            timestamp,
            limitations: vec![
                "[SIMULATION] Telemetry read from SimulatedNvmeController state machine; no physical kernel ioctl issued.".to_string(),
            ],
        }
    }

    // ── L4: Forensic validation (ForensicEngine Carving Pipeline) ──────────

    fn run_l4_forensic(&self, device: &Device, simulation_mode: bool) -> VerificationResult {
        let timestamp = Utc::now().to_rfc3339();
        let mut evidence = vec![];
        let mut limitations = vec![];

        if simulation_mode {
            let sample_buffer = vec![0u8; 64 * 1024];
            limitations.push("[SIMULATION] Evaluated against in-memory post-sanitization simulation buffer; flash controller internal wear-leveling spare area out-of-band.".to_string());

            let recovered = crate::forensic::engine::ForensicEngine::scan_bytes(&sample_buffer, &device.stable_id);
            let artifacts_found = recovered.len();
            let signatures_checked = 12;

            evidence.push(format!("[SIMULATION] Source: In-memory simulation buffer for '{}' ({} bytes)", device.stable_id, sample_buffer.len()));
            evidence.push("[SIMULATION] Scan Performed: Deep signature carving and container header analysis".to_string());
            evidence.push(format!("[SIMULATION] Signatures Checked: {} formats (JPEG, PNG, PDF, ZIP, ELF, SQLite, DOCX, etc.)", signatures_checked));
            evidence.push(format!("[SIMULATION] Candidate headers found: {}", artifacts_found));
            evidence.push(format!("[SIMULATION] Validated artifacts reconstructed: {}", artifacts_found));
            evidence.push(format!("[SIMULATION] Target artifact match status: {}", if artifacts_found == 0 { "0 target artifacts recovered" } else { "Remnants detected" }));

            let passed = artifacts_found == 0;

            VerificationResult {
                level: VerificationLevel::L4Forensic,
                status: if passed { VerificationStatus::Pass } else { VerificationStatus::Fail },
                method: "VANISH Deep Signature Carving & Bi-Fragment Reconstruction Scanner (Simulation)".to_string(),
                confidence_pct: 85,
                detail: format!(
                    "Forensic validation PASSED [SIMULATION]: 0 target artifacts recovered by VANISH carving pipeline on '{}'.",
                    device.stable_id
                ),
                evidence,
                timestamp,
                limitations,
            }
        } else {
            // REAL MODE: Read actual physical device sectors with sector alignment across 64MB sample range
            let scan_target_bytes = (64 * 1024 * 1024).min(device.capacity_bytes as usize);
            let sample_buffer = match Self::read_physical_sectors(&device.path, scan_target_bytes, device.logical_block_size as usize) {
                Ok(data) => {
                    limitations.push("Scanned host-accessible addressable sectors; retired/spare flash cells cannot be addressed over host bus.".to_string());
                    data
                }
                Err(e) => {
                    evidence.push(format!("Target path: '{}'", device.path));
                    evidence.push(format!("Physical read failure: {}", e));
                    evidence.push("OS error prevented reading raw sector stream from physical target.".to_string());
                    evidence.push("Reason L4 could not be completed: Insufficient device read access, parameter alignment error, or device detached.".to_string());
                    limitations.push(format!("Physical sector read error: {}", e));

                    return VerificationResult {
                        level: VerificationLevel::L4Forensic,
                        status: VerificationStatus::NotAvailable,
                        method: "VANISH Deep Signature Carving (Physical Media Direct Scan)".to_string(),
                        confidence_pct: 0,
                        detail: format!(
                            "Forensic validation NOT AVAILABLE: Cannot read raw sectors from physical target '{}' (OS Error: {}).",
                            device.path, e
                        ),
                        evidence,
                        timestamp,
                        limitations,
                    };
                }
            };

            let recovered = crate::forensic::engine::ForensicEngine::scan_bytes(&sample_buffer, &device.stable_id);
            let artifacts_found = recovered.len();
            let signatures_checked = 12;
            let sectors_read = sample_buffer.len() / (device.logical_block_size as usize).max(512);

            evidence.push(format!("Source: Physical addressable media '{}' (Capacity: {} bytes)", device.stable_id, device.capacity_bytes));
            evidence.push(format!("Scanned Range: LBA 0 to LBA {} (Byte offset 0 to {}, {:.2} MB)", sectors_read.saturating_sub(1), sample_buffer.len(), sample_buffer.len() as f64 / (1024.0 * 1024.0)));
            evidence.push("Scan Performed: Deep signature carving, container parser validation, and bi-fragment reconstruction on raw storage sectors".to_string());
            evidence.push(format!("Signatures Checked: {} formats (JPEG, PNG, PDF, ZIP, ELF, SQLite, DOCX, etc.)", signatures_checked));
            evidence.push(format!("Candidate headers found: {}", artifacts_found));
            evidence.push(format!("Validated artifacts reconstructed: {}", artifacts_found));
            evidence.push(format!("Target artifact match status: {}", if artifacts_found == 0 { "0 target artifacts recovered (Target file absence verified)" } else { "Remnants detected" }));

            let passed = artifacts_found == 0;

            VerificationResult {
                level: VerificationLevel::L4Forensic,
                status: if passed { VerificationStatus::Pass } else { VerificationStatus::Fail },
                method: "VANISH Deep Signature Carving & Bi-Fragment Reconstruction Scanner".to_string(),
                confidence_pct: if passed { 95 } else { 0 },
                detail: format!(
                    "Forensic validation {}: {} target artifacts recovered across {} bytes scanned on '{}'.",
                    if passed { "PASSED" } else { "FAILED" },
                    artifacts_found,
                    sample_buffer.len(),
                    device.stable_id
                ),
                evidence,
                timestamp,
                limitations,
            }
        }
    }

    /// Read physical raw sectors in sector-aligned chunks (immune to Windows Error 87)
    pub fn read_physical_sectors(path: &str, max_bytes: usize, block_size: usize) -> anyhow::Result<Vec<u8>> {
        let mut file = File::open(path)
            .map_err(|e| anyhow::anyhow!("Failed to open physical target '{}' for sector read: {}", path, e))?;

        file.seek(SeekFrom::Start(0))
            .map_err(|e| anyhow::anyhow!("Failed to seek to LBA 0 on '{}': {}", path, e))?;

        let sector = if block_size == 0 { 512 } else { block_size };
        let aligned_max = ((max_bytes + sector - 1) / sector) * sector;
        let mut buffer = vec![0u8; aligned_max];
        let mut total_read = 0;

        while total_read < aligned_max {
            let chunk = (64 * 1024).min(aligned_max - total_read);
            let chunk = (chunk / sector) * sector;
            if chunk == 0 {
                break;
            }
            match file.read(&mut buffer[total_read..total_read + chunk]) {
                Ok(0) => break,
                Ok(n) => total_read += n,
                Err(e) => {
                    if total_read > 0 {
                        break;
                    } else {
                        return Err(anyhow::anyhow!("Raw sector read error on '{}': {}", path, e));
                    }
                }
            }
        }

        if total_read == 0 {
            return Err(anyhow::anyhow!("Zero bytes read from raw physical device '{}'", path));
        }

        buffer.truncate(total_read);
        Ok(buffer)
    }
}

impl Default for VerificationEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Confidence scoring ────────────────────────────────────────────────────────

/// Compute overall weighted confidence score from per-level results.
/// Weights: L1=15%, L2=35%, L3=30%, L4=20%
fn compute_confidence_score(results: &[VerificationResult]) -> u8 {
    let weight = |level: &VerificationLevel| -> f64 {
        match level {
            VerificationLevel::L1Logical => 15.0,
            VerificationLevel::L2HostVisible => 35.0,
            VerificationLevel::L3DeviceReported => 30.0,
            VerificationLevel::L4Forensic => 20.0,
        }
    };

    let mut total_weight = 0.0f64;
    let mut weighted_score = 0.0f64;

    for r in results {
        if r.status == VerificationStatus::Unsupported || r.status == VerificationStatus::NotAvailable {
            // Skip unsupported or unavailable levels — redistribute weight proportionally
            continue;
        }
        let w = weight(&r.level);
        total_weight += w;
        let lvl_score = match r.status {
            VerificationStatus::Pass => r.confidence_pct as f64,
            VerificationStatus::Fail => 0.0,
            VerificationStatus::Inconclusive => 50.0,
            VerificationStatus::Unsupported | VerificationStatus::NotAvailable => 0.0,
        };
        weighted_score += w * lvl_score / 100.0;
    }

    if total_weight == 0.0 {
        return 0;
    }

    ((weighted_score / total_weight) * 100.0).round().min(100.0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_physical_sectors_aligned() {
        let mut temp = NamedTempFile::new().unwrap();
        let payload = vec![0xABu8; 4096];
        temp.write_all(&payload).unwrap();
        temp.flush().unwrap();

        let path = temp.path().to_str().unwrap();
        let read_bytes = VerificationEngine::read_physical_sectors(path, 1024, 512).unwrap();
        assert_eq!(read_bytes.len(), 1024);
        assert!(read_bytes.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_read_physical_sectors_nonexistent() {
        let res = VerificationEngine::read_physical_sectors("non_existent_disk_device_9999", 512, 512);
        assert!(res.is_err());
    }
}

