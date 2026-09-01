// VANISH Shared Frontend Types & API Contracts

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

export type LevelStatus =
  | 'Verified'
  | 'PartiallyVerified'
  | 'NotVerified'
  | 'Failed'
  | 'Unsupported';

export interface LevelVerificationDetail {
  status: LevelStatus;
  description: string;
  sectors_checked?: number;
  matching_expected_pattern_pct?: number;
  mean_entropy?: number;
}

export interface VerificationResult {
  verification_id: string;
  target_id: string;
  l1_logical: LevelVerificationDetail;
  l2_host_visible: LevelVerificationDetail;
  l3_device_reported: LevelVerificationDetail;
  l4_forensic_validation: LevelVerificationDetail;
  scope_description: string;
  warnings: string[];
  summary_statement: string;
}

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
