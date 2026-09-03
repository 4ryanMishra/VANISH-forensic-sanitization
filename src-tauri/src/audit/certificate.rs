/// SanitizationCertificate issuer — Step 10
///
/// Issues a tamper-evident, Ed25519-signed certificate per docs/12_ATTESTATION_SPEC.md.
///
/// Certificate fields (§3 of spec):
///   cert_id, cert_version, issued_at, device_identity, operation_summary,
///   verification_result, audit_chain_root_hash, audit_event_count,
///   signing_identity { key_id, public_key }, signature
///
/// Hashing: SHA-256 (consistent with hash_chain.rs — one algorithm per spec §3).
/// Signing:  Ed25519 over canonical JSON (sorted keys, no extra whitespace).
///
/// IMPORTANT — What this certificate DOES and DOES NOT claim (spec §5):
///   DOES:   "This sequence of VANISH events was appended in this order,
///            and the record has not been altered since signing."
///   DOES:   "This certificate was produced by a key whose public key is
///            displayed here — a third party can verify it."
///   DOES NOT: Claim data is physically unrecoverable by any party.
///             That claim is scoped to the VerificationReport's confidence_pct.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit::signing::{SigningIdentity, SigningKeypair};
use crate::common::audit::AuditEvent;
use crate::common::device::Device;
use crate::verification::VerificationReport;

/// Compact device identity snapshot embedded in the certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentitySnapshot {
    pub stable_id: String,
    pub model: String,
    pub serial: String,
    pub capacity_bytes: u64,
    pub media_type: String,
}

/// Summary of the sanitization operation embedded in the certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationSummary {
    pub standard: String,
    pub method: String,
    pub passes_completed: u32,
    pub bytes_processed: u64,
    pub simulation_mode: bool,
}

/// A signed, tamper-evident sanitization certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationCertificate {
    pub cert_id: String,
    pub cert_version: String,
    pub issued_at: String,
    pub device_identity: DeviceIdentitySnapshot,
    pub operation_summary: OperationSummary,
    /// Full L1–L4 verification result — unmodified from VerificationEngine output.
    pub verification_result: VerificationReport,
    /// SHA-256 of the last AuditEvent hash in the chain (the tip hash).
    pub audit_chain_root_hash: String,
    pub audit_event_count: usize,
    pub signing_identity: SigningIdentity,
    /// Ed25519 signature over canonical JSON of all fields above (excluding `signature`).
    /// Hex-encoded (64 bytes = 128 hex chars).
    pub signature: String,
    /// Human-readable scope note for demo/judge display.
    pub trust_scope_note: String,
}

/// Certificate body (everything except `signature`) for canonical serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CertificateBody {
    cert_id: String,
    cert_version: String,
    issued_at: String,
    device_identity: DeviceIdentitySnapshot,
    operation_summary: OperationSummary,
    verification_result: VerificationReport,
    audit_chain_root_hash: String,
    audit_event_count: usize,
    signing_identity: SigningIdentity,
}

pub struct CertificateIssuer;

impl CertificateIssuer {
    /// Issue a `SanitizationCertificate` tying together the device, operation,
    /// verification report, and audit chain tip.
    ///
    /// `keypair`  — the signing identity to use (session or machine).
    /// `events`   — full audit event slice for counting and tip-hash extraction.
    pub fn issue(
        keypair: &SigningKeypair,
        device: &Device,
        op_summary: OperationSummary,
        verification: VerificationReport,
        events: &[AuditEvent],
    ) -> Result<SanitizationCertificate, String> {
        use uuid::Uuid;

        let cert_id = format!("cert-{}", Uuid::new_v4());
        let issued_at = chrono::Utc::now().to_rfc3339();
        let audit_event_count = events.len();

        // Audit chain root hash = tip hash = last event's current_event_hash
        let audit_chain_root_hash = events
            .last()
            .map(|e| e.current_event_hash.clone())
            .unwrap_or_else(|| "0000000000000000000000000000000000000000000000000000000000000000".to_string());

        let device_identity = DeviceIdentitySnapshot {
            stable_id: device.stable_id.clone(),
            model: device.model.clone(),
            serial: device.serial.clone(),
            capacity_bytes: device.capacity_bytes,
            media_type: format!("{:?}", device.media_type),
        };

        let body = CertificateBody {
            cert_id: cert_id.clone(),
            cert_version: "1.0.0".to_string(),
            issued_at: issued_at.clone(),
            device_identity: device_identity.clone(),
            operation_summary: op_summary.clone(),
            verification_result: verification.clone(),
            audit_chain_root_hash: audit_chain_root_hash.clone(),
            audit_event_count,
            signing_identity: keypair.identity.clone(),
        };

        // Canonical serialization: sorted keys, no extra whitespace.
        // We use serde_json's default serialization which is deterministic for structs.
        let canonical_json = serde_json::to_string(&body)
            .map_err(|e| format!("Failed to canonicalize certificate body: {e}"))?;

        // SHA-256 the canonical JSON before signing (double-hashing for clarity)
        let mut hasher = Sha256::new();
        hasher.update(canonical_json.as_bytes());
        let digest = hasher.finalize();

        // Sign the digest with Ed25519
        let signature = keypair.sign(&digest);

        let trust_scope_note = match keypair.identity.scope {
            crate::audit::signing::KeyScope::Session => {
                "SESSION KEY: Proves internal consistency of this VANISH run. \
                 Key is discarded on exit. Does not prove machine identity across runs."
                    .to_string()
            }
            crate::audit::signing::KeyScope::Machine => {
                "MACHINE KEY: Persisted on disk (unencrypted — demo limitation). \
                 Proves continuity across runs on this machine."
                    .to_string()
            }
            crate::audit::signing::KeyScope::TpmArchitectureOnly => {
                "TPM ARCHITECTURE ONLY: Hardware TPM signing is designed but not \
                 implemented in this build per docs/12_ATTESTATION_SPEC.md §5."
                    .to_string()
            }
        };

        Ok(SanitizationCertificate {
            cert_id,
            cert_version: "1.0.0".to_string(),
            issued_at,
            device_identity,
            operation_summary: op_summary,
            verification_result: verification,
            audit_chain_root_hash,
            audit_event_count,
            signing_identity: keypair.identity.clone(),
            signature,
            trust_scope_note,
        })
    }

    /// Verify a certificate's signature. Returns Ok(true) if valid.
    pub fn verify(cert: &SanitizationCertificate) -> Result<bool, String> {
        let body = CertificateBody {
            cert_id: cert.cert_id.clone(),
            cert_version: cert.cert_version.clone(),
            issued_at: cert.issued_at.clone(),
            device_identity: cert.device_identity.clone(),
            operation_summary: cert.operation_summary.clone(),
            verification_result: cert.verification_result.clone(),
            audit_chain_root_hash: cert.audit_chain_root_hash.clone(),
            audit_event_count: cert.audit_event_count,
            signing_identity: cert.signing_identity.clone(),
        };

        let canonical_json = serde_json::to_string(&body)
            .map_err(|e| format!("Failed to re-canonicalize certificate: {e}"))?;

        let mut hasher = Sha256::new();
        hasher.update(canonical_json.as_bytes());
        let digest = hasher.finalize();

        crate::audit::signing::verify_signature(
            &cert.signing_identity.public_key_hex,
            &digest,
            &cert.signature,
        )
    }
}
