/// Integration tests for the VANISH Multi-Level Verification Engine (Step 9)
///
/// Covers:
///   - Shannon entropy correctness
///   - Block pattern checker correctness
///   - L1–L4 full engine run on simulated NVMe target
///   - L3 Unsupported behaviour for USB flash
///   - Confidence score computation
///   - Simulation mode labels present in evidence
#[cfg(test)]
mod tests {
    use vanish_core::common::device::{Device, Interface, MediaType};
    use vanish_core::verification::{
        VerificationEngine, VerificationLevel, VerificationRequest,
        LevelStatus,
    };
    use vanish_core::verification::sampling::{
        shannon_entropy, generate_simulated_samples, analyse_entropy,
        EntropyVerdict, ExpectedEntropyMode,
    };
    use vanish_core::verification::pattern::{
        check_block_pattern, ExpectedPattern, PatternCheckResult,
    };

    fn make_sandisk_device() -> Device {
        Device {
            stable_id: "disk-sandisk-16g".to_string(),
            path: "/dev/sdb".to_string(),
            model: "SanDisk Ultra USB 3.0".to_string(),
            serial: "4C530001230415116032".to_string(),
            capacity_bytes: 16_000_000_000,
            logical_block_size: 512,
            physical_block_size: 512,
            interface: Interface::Usb,
            media_type: MediaType::UsbFlash,
            mounted: false,
            mount_points: vec![],
            boot_device: false,
            system_disk: false,
            read_only: false,
            capabilities: vec!["HostBlockOverwrite".to_string()],
        }
    }

    fn make_nvme_sim_device() -> Device {
        Device {
            stable_id: "disk-sim-nvme-01".to_string(),
            path: "/dev/sim_nvme0n1".to_string(),
            model: "[Simulated] Enterprise NVMe SSD".to_string(),
            serial: "SIM-NVME-PURGE-9912".to_string(),
            capacity_bytes: 512_000_000_000,
            logical_block_size: 512,
            physical_block_size: 4096,
            interface: Interface::Nvme,
            media_type: MediaType::SsdNvme,
            mounted: false,
            mount_points: vec![],
            boot_device: false,
            system_disk: false,
            read_only: false,
            capabilities: vec![
                "NvmeSanitizeBlockErase".to_string(),
                "NvmeSanitizeCryptoErase".to_string(),
                "NvmeSanitizeOverwrite".to_string(),
            ],
        }
    }

    // ── Entropy tests ────────────────────────────────────────────────────────

    #[test]
    fn test_entropy_zero_block_near_zero() {
        let data = vec![0u8; 4096];
        assert!(shannon_entropy(&data) < 0.01);
    }

    #[test]
    fn test_entropy_high_for_varied_bytes() {
        let data: Vec<u8> = (0u16..256).flat_map(|i| std::iter::repeat(i as u8).take(16)).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.9, "Expected close to 8.0, got {e}");
    }

    #[test]
    fn test_simulated_zero_fill_entropy_verdict() {
        let samples = generate_simulated_samples(512_000_000, 512, 32, &ExpectedEntropyMode::ZeroFill);
        let analysis = analyse_entropy(&samples, &ExpectedEntropyMode::ZeroFill);
        assert_eq!(analysis.verdict, EntropyVerdict::CleanZeroFill);
        assert!(analysis.anomalous_lbas.is_empty());
    }

    #[test]
    fn test_simulated_random_overwrite_entropy_verdict() {
        let samples = generate_simulated_samples(512_000_000, 512, 32, &ExpectedEntropyMode::RandomOverwrite);
        let analysis = analyse_entropy(&samples, &ExpectedEntropyMode::RandomOverwrite);
        // Simulated pseudo-random should score clean random overwrite
        assert!(
            analysis.verdict == EntropyVerdict::CleanRandomOverwrite
                || analysis.verdict == EntropyVerdict::CleanHighEntropy,
            "Expected clean random, got {:?}", analysis.verdict
        );
    }

    // ── Pattern checker tests ────────────────────────────────────────────────

    #[test]
    fn test_pattern_zero_pass() {
        let data = vec![0x00u8; 512];
        assert_eq!(check_block_pattern(0, &data, &ExpectedPattern::Zero), PatternCheckResult::Passed);
    }

    #[test]
    fn test_pattern_zero_fail_detects_lba() {
        let mut data = vec![0x00u8; 512];
        data[7] = 0x4E;
        let result = check_block_pattern(99, &data, &ExpectedPattern::Zero);
        assert!(matches!(result, PatternCheckResult::Failed { first_violation_lba: 99, .. }));
    }

    #[test]
    fn test_pattern_random_not_applicable() {
        let data = vec![0xDEu8; 512];
        assert_eq!(
            check_block_pattern(0, &data, &ExpectedPattern::Random),
            PatternCheckResult::NotApplicable
        );
    }

    // ── Full engine L1–L4 on simulated NVMe ─────────────────────────────────

    #[test]
    fn test_full_nvme_verification_passes() {
        let engine = VerificationEngine::new();
        let device = make_nvme_sim_device();
        let req = VerificationRequest {
            device: device.clone(),
            levels_requested: vec![
                VerificationLevel::L1Logical,
                VerificationLevel::L2HostVisible,
                VerificationLevel::L3DeviceReported,
                VerificationLevel::L4Forensic,
            ],
            sanitization_method: "NvmeSanitizeCryptoErase".to_string(),
            simulation_mode: true,
        };
        let report = engine.run(&req);
        assert!(report.overall_passed, "Full NVMe verification should pass in simulation mode");
        assert!(report.confidence_pct >= 75, "Confidence should be ≥75%, got {}%", report.confidence_pct);
        assert_eq!(report.results.len(), 4);
    }

    // ── L3 Unsupported for USB flash ─────────────────────────────────────────

    #[test]
    fn test_l3_unsupported_for_usb_flash() {
        let engine = VerificationEngine::new();
        let device = make_sandisk_device();
        let req = VerificationRequest {
            device: device.clone(),
            levels_requested: vec![
                VerificationLevel::L1Logical,
                VerificationLevel::L2HostVisible,
                VerificationLevel::L3DeviceReported,
            ],
            sanitization_method: "SinglePassZero".to_string(),
            simulation_mode: true,
        };
        let report = engine.run(&req);

        let l3_result = report.results.iter().find(|r| r.level == VerificationLevel::L3DeviceReported);
        assert!(l3_result.is_some(), "L3 result should be present");
        assert_eq!(l3_result.unwrap().status, LevelStatus::Unsupported, "L3 must be Unsupported for USB flash");

        // Overall should still pass because Unsupported is not a failure
        assert!(report.overall_passed, "Report should pass with L3=Unsupported");
        assert!(report.unsupported_levels.contains(&VerificationLevel::L3DeviceReported));
    }

    // ── Simulation labels in evidence ────────────────────────────────────────

    #[test]
    fn test_simulation_label_in_evidence() {
        let engine = VerificationEngine::new();
        let device = make_nvme_sim_device();
        let req = VerificationRequest {
            device,
            levels_requested: vec![VerificationLevel::L2HostVisible],
            sanitization_method: "NvmeSanitizeBlockErase".to_string(),
            simulation_mode: true,
        };
        let report = engine.run(&req);
        let l2 = report.results.iter().find(|r| r.level == VerificationLevel::L2HostVisible).unwrap();
        let has_sim_label = l2.evidence.iter().any(|e| e.contains("[SIM]"));
        assert!(has_sim_label, "Evidence must contain [SIM] label in simulation mode per docs/08_PHYSICAL_LAB.md");
    }

    // ── Confidence score: lower when simulation ──────────────────────────────

    #[test]
    fn test_confidence_lower_in_simulation_vs_physical() {
        let engine = VerificationEngine::new();
        let device = make_nvme_sim_device();

        let req_sim = VerificationRequest {
            device: device.clone(),
            levels_requested: vec![
                VerificationLevel::L1Logical,
                VerificationLevel::L2HostVisible,
                VerificationLevel::L3DeviceReported,
            ],
            sanitization_method: "NvmeSanitizeCryptoErase".to_string(),
            simulation_mode: true,
        };
        let req_phys = VerificationRequest {
            simulation_mode: false,
            ..req_sim.clone()
        };

        let report_sim = engine.run(&req_sim);
        let report_phys = engine.run(&req_phys);

        assert!(
            report_sim.confidence_pct <= report_phys.confidence_pct,
            "Simulation confidence ({}) should be ≤ physical confidence ({})",
            report_sim.confidence_pct, report_phys.confidence_pct
        );
    }
}
