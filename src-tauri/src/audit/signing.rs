/// VANISH Ed25519 Signing Identity Module (Step 10)
///
/// Implements session and machine-persisted Ed25519 signing keys for
/// binding SanitizationCertificates to a verifiable identity.
///
/// Scope: Aryan's Agent A ownership per docs/12_ATTESTATION_SPEC.md §6.
///
/// Key hierarchy implemented (per spec §2):
///   (1) Session key  — fresh per VANISH run, held in memory only.
///   (2) Machine key  — persisted to disk in `~/.vanish/machine_key.json`
///                      (unencrypted; noted as demo limitation in spec §2).
///   (3) TPM-anchored — ARCHITECTED ONLY, NOT IMPLEMENTED.
///                      Noted as stretch goal per docs/12_ATTESTATION_SPEC.md §5.
///
/// LIMITATION: This does NOT claim TPM-level trust. Private key storage is
/// software-only. The certificate proves internal consistency and session
/// authorship — see docs/12_ATTESTATION_SPEC.md §5 for explicit scope bounds.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The key scope determines trust level and lifetime.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KeyScope {
    /// Session: generated per-run, discarded on exit. Cheapest trust level.
    Session,
    /// Machine: persisted to disk, proves continuity across runs.
    Machine,
    /// Tpm: key sealed in hardware TPM — ARCHITECTED ONLY, not implemented.
    #[serde(rename = "tpm_architecture_only")]
    TpmArchitectureOnly,
}

/// Identifies the signing public key used on a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningIdentity {
    /// Unique key ID (hex-encoded SHA-256 of public key bytes).
    pub key_id: String,
    /// Ed25519 public key, hex-encoded (32 bytes = 64 hex chars).
    pub public_key_hex: String,
    pub scope: KeyScope,
    pub created_at: String,
}

/// A loaded signing keypair ready to sign certificate payloads.
pub struct SigningKeypair {
    pub identity: SigningIdentity,
    /// The private signing key (kept in memory only — not serialized).
    signing_key: SigningKey,
}

impl SigningKeypair {
    /// Generate a fresh session keypair. Discarded when `SigningKeypair` is dropped.
    pub fn generate_session() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self::from_key(signing_key, KeyScope::Session)
    }

    /// Load or generate a machine-persisted keypair.
    /// If the key file doesn't exist, generates and saves a new one.
    /// The key is stored unencrypted — acceptable for demo; noted as limitation.
    pub fn load_or_generate_machine(key_dir: &PathBuf) -> Result<Self, String> {
        let key_file = key_dir.join("machine_key.json");

        if key_file.exists() {
            let contents = std::fs::read_to_string(&key_file)
                .map_err(|e| format!("Failed to read machine key: {e}"))?;
            let stored: StoredMachineKey = serde_json::from_str(&contents)
                .map_err(|e| format!("Failed to parse machine key: {e}"))?;

            let key_bytes = hex::decode(&stored.signing_key_hex)
                .map_err(|e| format!("Failed to decode signing key hex: {e}"))?;
            let key_array: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| "Signing key must be 32 bytes".to_string())?;
            let signing_key = SigningKey::from_bytes(&key_array);
            Ok(Self::from_key(signing_key, KeyScope::Machine))
        } else {
            std::fs::create_dir_all(key_dir)
                .map_err(|e| format!("Failed to create key directory: {e}"))?;

            let mut csprng = OsRng;
            let signing_key = SigningKey::generate(&mut csprng);
            let keypair = Self::from_key(signing_key, KeyScope::Machine);

            // Persist private key bytes (unencrypted — see LIMITATION above)
            let stored = StoredMachineKey {
                signing_key_hex: hex::encode(keypair.signing_key.to_bytes()),
                public_key_hex: keypair.identity.public_key_hex.clone(),
                key_id: keypair.identity.key_id.clone(),
                created_at: keypair.identity.created_at.clone(),
            };
            let json = serde_json::to_string_pretty(&stored)
                .map_err(|e| format!("Failed to serialize machine key: {e}"))?;
            std::fs::write(&key_file, json)
                .map_err(|e| format!("Failed to write machine key: {e}"))?;

            Ok(keypair)
        }
    }

    /// Sign a canonical payload (bytes). Returns hex-encoded Ed25519 signature.
    pub fn sign(&self, payload: &[u8]) -> String {
        let sig: Signature = self.signing_key.sign(payload);
        hex::encode(sig.to_bytes())
    }

    fn from_key(signing_key: SigningKey, scope: KeyScope) -> Self {
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let pub_hex = hex::encode(verifying_key.to_bytes());

        // key_id = hex(SHA-256(public_key_bytes))
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(verifying_key.to_bytes());
        let key_id = hex::encode(hasher.finalize());

        let created_at = chrono::Utc::now().to_rfc3339();

        Self {
            identity: SigningIdentity {
                key_id,
                public_key_hex: pub_hex,
                scope,
                created_at,
            },
            signing_key,
        }
    }
}

/// Verify an Ed25519 signature over a payload given a hex-encoded public key and signature.
pub fn verify_signature(public_key_hex: &str, payload: &[u8], signature_hex: &str) -> Result<bool, String> {
    let pub_bytes = hex::decode(public_key_hex)
        .map_err(|e| format!("Failed to decode public key: {e}"))?;
    let pub_array: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| "Public key must be 32 bytes".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&pub_array)
        .map_err(|e| format!("Invalid public key: {e}"))?;

    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| format!("Failed to decode signature: {e}"))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "Signature must be 64 bytes".to_string())?;
    let signature = Signature::from_bytes(&sig_array);

    use ed25519_dalek::Verifier;
    Ok(verifying_key.verify(payload, &signature).is_ok())
}

/// Internal format for machine key persistence (unencrypted, demo only).
#[derive(Debug, Serialize, Deserialize)]
struct StoredMachineKey {
    signing_key_hex: String,
    public_key_hex: String,
    key_id: String,
    created_at: String,
}
