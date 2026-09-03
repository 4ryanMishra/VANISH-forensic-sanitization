// VANISH Shared Frontend Types & API Contracts
// Aryan's module owns: Device, SanitizationPlan, VerificationReport, SanitizationCertificate

// ── Hashing layer ─────────────────────────────────────────────────────────────
// Consumed from backend; no hashing logic lives in the UI.
// Shape mirrors common/hashing.py output.

export type HashAlgorithm = 'SHA-256' | 'BLAKE3';

export type HashPurpose =
  | 'canonical_evidence'   // SHA-256 only — artifact identity, image integrity, report verification
  | 'internal_processing'; // BLAKE3 only — large storage scans, chunk hashing, deduplication, caching

export interface HashResult {
  algorithm: HashAlgorithm;
  digest: string;          // hex-encoded digest from backend
  purpose: HashPurpose;
  source_label: string;    // human-readable description of what was hashed
  computed_at: string;     // ISO 8601 timestamp from backend
  simulation_mode: boolean;
}

export interface HashStatusReport {
  results: HashResult[];
  backend_available: boolean;
}


export type MediaType =
  | 'Hdd'
  | 'SsdNvme'
  | 'SsdSata'
  | 'UsbFlash'
  | 'SdCard'
  | 'VirtualDisk'
  | { Unknown: string };

export type InterfaceType =
  | 'Nvme'
  | 'Sata'
  | 'Scsi'
  | 'Usb'
  | 'Mmc'
  | 'Virtual'
  | { Unknown: string };

export type DeviceCapability =
  | 'NvmeFormatCryptoErase'
  | 'NvmeFormatUserErase'
  | 'NvmeSanitizeBlockErase'
  | 'NvmeSanitizeCryptoErase'
  | 'NvmeSanitizeOverwrite'
  | 'AtaSecureErase'
  | 'AtaEnhancedSecureErase'
  | 'AtaSanitizeCrypto'
  | 'AtaSanitizeBlock'
  | 'ScsiSanitize'
  | 'HostBlockOverwrite'
  | 'TrimSupported'
  | 'ReadOnlySwitchPresent'
  | 'SmartHealthQuery';

export interface Device {
  stable_id: string;
  path: string;
  model: string;
  serial: string;
  capacity_bytes: number;
  logical_block_size: number;
  physical_block_size: number;
  interface: InterfaceType;
  media_type: MediaType;
  mounted: boolean;
  mount_points: string[];
  boot_device: boolean;
  system_disk: boolean;
  read_only: boolean;
  capabilities: DeviceCapability[];
}

// ── Sanitization layer ────────────────────────────────────────────────────────

export type SanitizationStandard =
  | 'Nist80088Clear'
  | 'Nist80088Purge'
  | 'Dod522022M3Pass'
  | 'Ieee2883Purge'
  | 'SinglePassZero'
  | 'SinglePassRandom'
  | 'CustomPattern';

export type SanitizationMethod =
  | 'NvmeSanitizeBlockErase'
  | 'NvmeSanitizeCryptoErase'
  | 'NvmeSanitizeOverwrite'
  | 'AtaSecureErase'
  | 'AtaEnhancedSecureErase'
  | { HostSequentialOverwrite: { passes: number; pattern_desc: string } }
  | { FileTargetedShredding: { passes: number; zero_slack: boolean } }
  | 'SimulatedSanitization';

export interface SanitizationPlan {
  plan_id: string;
  target_id: string;
  standard: SanitizationStandard;
  method: SanitizationMethod;
  rationale: string;
  prerequisites: string[];
  warnings: string[];
  estimated_duration_seconds?: number;
  verification_levels_planned: string[];
  simulation_mode: boolean;
}

// ── Verification Engine — Step 9 (new backend shape) ─────────────────────────

export type VerificationLevel =
  | 'L1Logical'
  | 'L2HostVisible'
  | 'L3DeviceReported'
  | 'L4Forensic';

export type LevelStatusCode =
  | 'PASSED'
  | 'UNSUPPORTED'
  | 'FAILED'
  | 'ERROR';

export interface LevelResult {
  level: VerificationLevel;
  status: LevelStatusCode;
  confidence_pct: number;
  detail: string;
  evidence: string[];
}

export interface VerificationReport {
  target_id: string;
  levels_executed: VerificationLevel[];
  results: LevelResult[];
  overall_passed: boolean;
  confidence_pct: number;
  timestamp_utc: string;
  unsupported_levels: VerificationLevel[];
}

// ── Attestation / Certificate — Step 10 ──────────────────────────────────────

export type KeyScope = 'session' | 'machine' | 'tpm_architecture_only';

export interface SigningIdentity {
  key_id: string;
  public_key_hex: string;
  scope: KeyScope;
  created_at: string;
}

export interface DeviceIdentitySnapshot {
  stable_id: string;
  model: string;
  serial: string;
  capacity_bytes: number;
  media_type: string;
}

export interface OperationSummary {
  standard: string;
  method: string;
  passes_completed: number;
  bytes_processed: number;
  simulation_mode: boolean;
}

export interface SanitizationCertificate {
  cert_id: string;
  cert_version: string;
  issued_at: string;
  device_identity: DeviceIdentitySnapshot;
  operation_summary: OperationSummary;
  verification_result: VerificationReport;
  audit_chain_root_hash: string;
  audit_event_count: number;
  signing_identity: SigningIdentity;
  signature: string;
  trust_scope_note: string;
}

// ── Audit chain ───────────────────────────────────────────────────────────────

export type AuditActor =
  | { User: string }
  | 'SystemEngine'
  | 'AutomatedPolicy';

export interface AuditEvent {
  event_id: string;
  sequence_number: number;
  timestamp: string;
  actor: AuditActor;
  operation: string;
  target_id: string;
  parameters_json: string;
  result_status: string;
  verification_summary?: string;
  error_message?: string;
  previous_event_hash: string;
  current_event_hash: string;
}

// ── Forensic recovery (Subodeep's contract — shared types only) ───────────────

export type ArtifactFormat =
  | 'Jpeg'
  | 'Pdf'
  | 'Zip'
  | 'Png'
  | 'Sqlite'
  | 'PlainText'
  | { Unknown: string };

export type ValidationStatus =
  | 'Valid'
  | 'Corrupted'
  | 'Truncated'
  | 'Unverified';

export type CarvingMethod =
  | 'ContiguousSignature'
  | 'FragmentedReconstruction'
  | 'FilesystemMetadata'
  | 'RawScan';

export interface ArtifactProvenance {
  source_id: string;
  detection_method: CarvingMethod;
  sector_ranges: [number, number][];
  entropy_score: number;
  header_magic: string;
}

export interface RecoveredArtifact {
  artifact_id: string;
  source_id: string;
  source_offsets: [number, number][];
  format: ArtifactFormat;
  original_path?: string;
  extracted_path?: string;
  size_bytes: number;
  sha256: string;
  validation_status: ValidationStatus;
  confidence_score: number;
  provenance: ArtifactProvenance;
}

export interface RecoveryJob {
  job_id: string;
  source_path: string;
  scan_mode: string;
  simulation_mode: boolean;
  created_at_utc: string;
}

export interface RecoveryResult {
  job_id: string;
  source_id: string;
  total_scanned_bytes: number;
  artifacts: RecoveredArtifact[];
  simulation_mode: boolean;
  execution_time_ms: number;
  summary_notes: string;
}

// ── Job tracking ──────────────────────────────────────────────────────────────

export type JobState =
  | 'Created'
  | 'Validating'
  | 'Ready'
  | 'Armed'
  | 'Running'
  | 'Verifying'
  | 'Completed'
  | 'Failed'
  | 'Cancelled';

export interface JobProgress {
  current_phase: string;
  bytes_processed: number;
  total_bytes: number;
  percentage: number;
  eta_seconds?: number;
}

export interface Job {
  job_id: string;
  job_type: string;
  state: JobState;
  target_id: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  progress?: JobProgress;
  error?: string;
}
