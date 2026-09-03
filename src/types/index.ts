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
  is_simulated: boolean;
  capabilities: DeviceCapability[];
}

// ── Safety Gate Layer ────────────────────────────────────────────────────────

export type SafetyCheckStatus = 'Pass' | 'Fail' | 'Warning' | 'Unknown' | 'Blocked';
export type SafetySeverity = 'Info' | 'Warning' | 'High' | 'Critical';

export interface ExecutionTargetSnapshot {
  stable_id: string;
  path: string;
  model: string;
  serial: string;
  capacity_bytes: number;
  logical_block_size: number;
  physical_block_size: number;
  interface: InterfaceType;
  media_type: MediaType;
  is_simulated: boolean;
  capabilities: DeviceCapability[];
  snapshot_timestamp_utc: string;
  fingerprint_sha256: string;
}

export interface SafetyCheck {
  check: string;
  status: SafetyCheckStatus;
  severity: SafetySeverity;
  message: string;
  evidence: string[];
}

export interface SafetyEvaluationReport {
  passed: boolean;
  target_id: string;
  checks: SafetyCheck[];
  target_snapshot?: ExecutionTargetSnapshot;
  evaluated_at_utc: string;
  abort_reason?: string;
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

// ── Verification Engine (Truthful 4-Level Matrix) ─────────────────────────

export type VerificationLevel =
  | 'L1Logical'
  | 'L2HostVisible'
  | 'L3DeviceReported'
  | 'L4Forensic';

export type VerificationStatus =
  | 'PASS'
  | 'FAIL'
  | 'NOT_AVAILABLE'
  | 'UNSUPPORTED'
  | 'INCONCLUSIVE'
  | 'PASSED'
  | 'FAILED'
  | 'ERROR';

export type LevelStatusCode = VerificationStatus;

export interface VerificationResult {
  level: VerificationLevel;
  status: VerificationStatus;
  method: string;
  evidence: string[];
  timestamp: string;
  limitations: string[];
  confidence_pct: number;
  detail: string;
}

export type LevelResult = VerificationResult;

export interface VerificationReport {
  target_id: string;
  levels_executed: VerificationLevel[];
  results: VerificationResult[];
  overall_passed: boolean;
  confidence_pct: number;
  timestamp_utc: string;
  unsupported_levels: VerificationLevel[];
  is_simulation?: boolean;
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
  | 'Unverified'
  | 'FalsePositive';

export type CarvingMethod =
  | 'ContiguousSignature'
  | 'FragmentedReconstruction'
  | 'FilesystemMetadata'
  | 'RawScan';

export interface FragmentRecord {
  sequence_index: number;
  start_offset: number;
  length_bytes: number;
  sector_start: number;
  sector_end: number;
}

export interface ArtifactProvenance {
  source_id: string;
  source_type_desc: string;
  detection_method: CarvingMethod;
  validation_method: string;
  sector_ranges: [number, number][];
  fragments: FragmentRecord[];
  entropy_score: number;
  header_magic: string;
  recovery_timestamp_utc: string;
}

export interface RecoveredArtifact {
  artifact_id: string;
  source_id: string;
  source_hash?: string;
  source_offsets: [number, number][];
  format: ArtifactFormat;
  original_path?: string;
  extracted_path?: string;
  size_bytes: number;
  sha256: string; // Canonical forensic evidence hash
  optional_blake3?: string; // High-throughput internal processing hash
  validation_status: ValidationStatus;
  validation_method: string;
  confidence_score: number;
  timestamp_utc: string;
  provenance: ArtifactProvenance;
  data_base64?: string;
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

// ── Cryptographic Hashing Status ─────────────────────────────────────────────

export interface HashResult {
  algorithm: 'SHA-256' | 'BLAKE3';
  digest: string;
  purpose: 'canonical_evidence' | 'internal_processing';
  source_label: string;
  computed_at: string;
  simulation_mode: boolean;
}

export interface HashStatusReport {
  results: HashResult[];
  backend_available: boolean;
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
