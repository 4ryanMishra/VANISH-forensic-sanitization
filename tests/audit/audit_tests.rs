/// Tests for the VANISH Audit & Attestation system (Step 10)
///
/// Covers:
///   - AuditChain hash-chain integrity verification
///   - SigningKeypair generation (session scope)
///   - Ed25519 sign → verify round-trip
///   - SanitizationCertificate issuance and verify
///   - Certificate tamper detection (signature fails after body mutation)
///   - trust_scope_note correctly set for session key
#[cfg(test)]
mod tests {
    use vanish_core::audit::{
        AuditChain, CertificateIssuer, OperationSummary, SigningKeypair,
    };
    use vanish_core::audit::signing::{KeyScope, verify_signature};
    use vanish_core::common::audit::AuditActor;
    use vanish_core::common::device::{Device, Interface, MediaType};
    use vanish_core::verification::{
        VerificationEngine, VerificationLevel, VerificationReport, VerificationRequest,
    };

    fn make_test_device() -> Device {
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

    fn make_verification_report(device: &Device) -> VerificationReport {
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
        VerificationEngine::new().run(&req)
    }

    // ── AuditChain tests ─────────────────────────────────────────────────────

    #[test]
    fn test_audit_chain_integrity_passes_for_untampered_chain() {
        let mut chain = AuditChain::new();
        chain.append_event(
            AuditActor::SystemEngine,
            "TEST_OP_1".to_string(),
            "device-a".to_string(),
            "{}".to_string(),
            "SUCCESS".to_string(),
            None,
            None,
        );
        chain.append_event(
            AuditActor::SystemEngine,
            "TEST_OP_2".to_string(),
            "device-a".to_string(),
            "{}".to_string(),
            "SUCCESS".to_string(),
            None,
            None,
        );
        assert!(chain.verify_integrity(), "Untampered chain must verify");
    }

    #[test]
    fn test_audit_chain_hashes_linked() {
        let mut chain = AuditChain::new();
        let e1 = chain.append_event(
            AuditActor::SystemEngine,
            "OP_A".to_string(),
            "dev".to_string(),
            "{}".to_string(),
            "SUCCESS".to_string(),
            None,
            None,
        );
        let e2 = chain.append_event(
            AuditActor::SystemEngine,
            "OP_B".to_string(),
            "dev".to_string(),
            "{}".to_string(),
            "SUCCESS".to_string(),
            None,
            None,
        );
        assert_eq!(e2.previous_event_hash, e1.current_event_hash, "Events must be hash-linked");
    }

    // ── Signing tests ────────────────────────────────────────────────────────

    #[test]
    fn test_session_keypair_scope() {
        let kp = SigningKeypair::generate_session();
        assert_eq!(kp.identity.scope, KeyScope::Session);
        assert_eq!(kp.identity.public_key_hex.len(), 64, "Public key must be 64 hex chars (32 bytes)");
        assert_eq!(kp.identity.key_id.len(), 64, "Key ID must be 64 hex chars (SHA-256)");
    }

    #[test]
    fn test_sign_verify_round_trip() {
        let kp = SigningKeypair::generate_session();
        let payload = b"vanish test payload for ed25519 signing";
        let sig = kp.sign(payload);
        let valid = verify_signature(&kp.identity.public_key_hex, payload, &sig)
            .expect("Verify should not error");
        assert!(valid, "Signature must verify against its own public key");
    }

    #[test]
    fn test_sign_verify_wrong_payload_fails() {
        let kp = SigningKeypair::generate_session();
        let sig = kp.sign(b"original payload");
        let valid = verify_signature(&kp.identity.public_key_hex, b"tampered payload", &sig)
            .expect("Verify should not error");
        assert!(!valid, "Signature must NOT verify against a different payload");
    }

    #[test]
    fn test_sign_verify_wrong_key_fails() {
        let kp1 = SigningKeypair::generate_session();
        let kp2 = SigningKeypair::generate_session();
        let payload = b"some payload";
        let sig = kp1.sign(payload);
        let valid = verify_signature(&kp2.identity.public_key_hex, payload, &sig)
            .expect("Verify should not error");
        assert!(!valid, "Signature from key1 must NOT verify against key2");
    }

    // ── Certificate tests ────────────────────────────────────────────────────

    #[test]
    fn test_certificate_issuance_and_verification() {
        let kp = SigningKeypair::generate_session();
        let device = make_test_device();
        let verification = make_verification_report(&device);

        let mut chain = AuditChain::new();
        chain.append_event(
            AuditActor::SystemEngine,
            "SANITIZATION_EXECUTION: SinglePassZero".to_string(),
            device.stable_id.clone(),
            "{}".to_string(),
            "SUCCESS".to_string(),
            None,
            None,
        );
        let events: Vec<_> = chain.get_events().to_vec();

        let op_summary = OperationSummary {
            standard: "SinglePassZero".to_string(),
            method: "SinglePassZero".to_string(),
            passes_completed: 1,
            bytes_processed: device.capacity_bytes,
            simulation_mode: true,
        };

        let cert = CertificateIssuer::issue(&kp, &device, op_summary, verification, &events)
            .expect("Certificate issuance should succeed");

        assert!(!cert.cert_id.is_empty());
        assert_eq!(cert.cert_version, "1.0.0");
        assert!(!cert.signature.is_empty());
        assert!(cert.trust_scope_note.contains("SESSION KEY"));

        let valid = CertificateIssuer::verify(&cert).expect("Verification should not error");
        assert!(valid, "Freshly issued certificate must verify");
    }

    #[test]
    fn test_certificate_tamper_detected() {
        let kp = SigningKeypair::generate_session();
        let device = make_test_device();
        let verification = make_verification_report(&device);
        let events = vec![];

        let op_summary = OperationSummary {
            standard: "SinglePassZero".to_string(),
            method: "SinglePassZero".to_string(),
            passes_completed: 1,
            bytes_processed: 1024,
            simulation_mode: true,
        };

        let mut cert = CertificateIssuer::issue(&kp, &device, op_summary, verification, &events)
            .expect("Certificate issuance should succeed");

        // Tamper: change the device serial in the certificate body
        cert.device_identity.serial = "TAMPERED-SERIAL-000".to_string();

        let valid = CertificateIssuer::verify(&cert).expect("Verify call should not error");
        assert!(!valid, "Tampered certificate must NOT verify");
    }

    #[test]
    fn test_certificate_audit_chain_tip_hash_correct() {
        let kp = SigningKeypair::generate_session();
        let device = make_test_device();
        let verification = make_verification_report(&device);

        let mut chain = AuditChain::new();
        let e = chain.append_event(
            AuditActor::SystemEngine,
            "SANITIZATION_EXECUTION: SinglePassZero".to_string(),
            device.stable_id.clone(),
            "{}".to_string(),
            "SUCCESS".to_string(),
            None,
            None,
        );
        let events: Vec<_> = chain.get_events().to_vec();

        let op_summary = OperationSummary {
            standard: "SinglePassZero".to_string(),
            method: "SinglePassZero".to_string(),
            passes_completed: 1,
            bytes_processed: 1024,
            simulation_mode: true,
        };

        let cert = CertificateIssuer::issue(&kp, &device, op_summary, verification, &events)
            .expect("Issue should succeed");

        assert_eq!(
            cert.audit_chain_root_hash, e.current_event_hash,
            "Cert audit_chain_root_hash must equal the chain tip hash"
        );
        assert_eq!(cert.audit_event_count, 1);
    }
}
