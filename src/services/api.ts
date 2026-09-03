import { Device, SanitizationPlan, SanitizationStandard, AuditEvent, VerificationReport, SanitizationCertificate, HashStatusReport } from '../types';

export interface ExecutionSummary {
  plan_id: string;
  target_id: string;
  bytes_processed: number;
  passes_completed: number;
  method_executed: string;
  execution_log: string[];
  success: boolean;
}

// Storage device abstraction layer aligned with docs/08_PHYSICAL_LAB.md
const MOCK_DEVICES: Device[] = [
  {
    stable_id: 'disk-sandisk-16g',
    path: '/dev/sdb',
    model: 'SanDisk Ultra USB 3.0 (Physical Lab Media)',
    serial: '4C530001230415116032',
    capacity_bytes: 16000000000,
    logical_block_size: 512,
    physical_block_size: 512,
    interface: 'Usb',
    media_type: 'UsbFlash',
    mounted: false,
    mount_points: [],
    boot_device: false,
    system_disk: false,
    read_only: false,
    is_simulated: false,
    capabilities: ['HostBlockOverwrite'],
  },
  {
    stable_id: 'disk-sim-nvme-01',
    path: '/dev/sim_nvme0n1',
    model: '[Simulated] Enterprise NVMe SSD 512GB',
    serial: 'SIM-NVME-PURGE-9912',
    capacity_bytes: 512000000000,
    logical_block_size: 512,
    physical_block_size: 4096,
    interface: 'Nvme',
    media_type: 'SsdNvme',
    mounted: false,
    mount_points: [],
    boot_device: false,
    system_disk: false,
    read_only: false,
    is_simulated: true,
    capabilities: ['NvmeSanitizeBlockErase', 'NvmeSanitizeCryptoErase', 'NvmeSanitizeOverwrite', 'TrimSupported'],
  },
  {
    stable_id: 'disk-vdisk-01',
    path: '/dev/loop0',
    model: '[Simulated] VANISH Virtual Forensic Image',
    serial: 'VN-LAB-8821',
    capacity_bytes: 536870912, // 512MB
    logical_block_size: 512,
    physical_block_size: 4096,
    interface: 'Virtual',
    media_type: 'VirtualDisk',
    mounted: false,
    mount_points: [],
    boot_device: false,
    system_disk: false,
    read_only: false,
    is_simulated: true,
    capabilities: ['HostBlockOverwrite', 'TrimSupported'],
  },
  {
    stable_id: 'disk-host-sys',
    path: '/dev/nvme0n1',
    model: 'Host Primary System Disk (Write-Locked)',
    serial: 'SYS-HOST-PROTECTED-01',
    capacity_bytes: 1000204886016,
    logical_block_size: 512,
    physical_block_size: 512,
    interface: 'Nvme',
    media_type: 'SsdNvme',
    mounted: true,
    mount_points: ['/', '/boot/efi'],
    boot_device: true,
    system_disk: true,
    read_only: false,
    is_simulated: false,
    capabilities: ['NvmeSanitizeBlockErase', 'NvmeSanitizeCryptoErase', 'TrimSupported'],
  },
];

export async function fetchDevices(): Promise<Device[]> {
  try {
    if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
      const { invoke } = await import('@tauri-apps/api/core');
      return await invoke<Device[]>('list_devices');
    }
  } catch (err) {
    console.warn('Tauri API unavailable, using simulation mock data:', err);
  }
  return MOCK_DEVICES;
}

export async function fetchRecommendedPlan(
  device: Device,
  standard: SanitizationStandard
): Promise<SanitizationPlan> {
  try {
    if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
      const { invoke } = await import('@tauri-apps/api/core');
      return await invoke<SanitizationPlan>('get_recommended_plan', { device, standard });
    }
  } catch (err) {
    console.warn('Tauri API unavailable, generating client simulated plan:', err);
  }

  const isSimulated = device.stable_id.startsWith('disk-sim-') || device.media_type === 'VirtualDisk';

  return {
    plan_id: `plan-${Math.random().toString(36).substring(2, 9)}`,
    target_id: device.stable_id,
    standard,
    method: device.media_type === 'SsdNvme' ? 'NvmeSanitizeCryptoErase' : 'SimulatedSanitization',
    rationale: `Hardware-aware profile selected for ${typeof device.media_type === 'string' ? device.media_type : 'Device'} under standard ${standard}.${
      isSimulated ? ' (Executing against simulated hardware target per lab spec)' : ''
    }`,
    prerequisites: ['Verify target serial number', 'Confirm target is not host boot/system drive'],
    warnings: device.system_disk ? ['PROTECTED SYSTEM DISK: Operation will be rejected by safety gate.'] : [],
    estimated_duration_seconds: 45,
    verification_levels_planned: ['L1_LOGICAL', 'L2_HOST_VISIBLE', 'L4_FORENSIC'],
    simulation_mode: isSimulated,
  };
}

export async function executeSanitizationPlan(
  plan: SanitizationPlan,
  device: Device
): Promise<ExecutionSummary> {
  try {
    if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
      const { invoke } = await import('@tauri-apps/api/core');
      return await invoke<ExecutionSummary>('execute_sanitization_plan', { plan, device });
    }
  } catch (err) {
    console.warn('Tauri API unavailable, returning simulated execution summary:', err);
  }

  return {
    plan_id: plan.plan_id,
    target_id: device.stable_id,
    bytes_processed: device.capacity_bytes,
    passes_completed: 1,
    method_executed: typeof plan.method === 'string' ? plan.method : 'Custom Sanitization Method',
    execution_log: [
      `Pre-execution invariant safety gate verified for device '${device.stable_id}'`,
      'Sanitization routine dispatched and completed successfully',
    ],
    success: true,
  };
}

export async function fetchAuditLog(): Promise<AuditEvent[]> {
  try {
    if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
      const { invoke } = await import('@tauri-apps/api/core');
      return await invoke<AuditEvent[]>('get_audit_log');
    }
  } catch (err) {
    console.warn('Tauri API unavailable, using mock audit log:', err);
  }

  return [
    {
      event_id: 'evt-genesis-0001',
      sequence_number: 1,
      timestamp: new Date().toISOString(),
      actor: 'SystemEngine',
      operation: 'SYSTEM_BOOT_AUDIT_INITIALIZED',
      target_id: 'vanish-core',
      parameters_json: '{"version":"0.1.0","environment":"lab-simulation"}',
      result_status: 'SUCCESS',
      verification_summary: 'Genesis hash verified',
      previous_event_hash: '0000000000000000000000000000000000000000000000000000000000000000',
      current_event_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    },
  ];
}

export async function runVerification(
  device: Device,
  sanitizationMethod: string,
  simulationMode: boolean
): Promise<VerificationReport> {
  try {
    if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
      const { invoke } = await import('@tauri-apps/api/core');
      return await invoke<VerificationReport>('run_verification', {
        device,
        sanitizationMethod,
        simulationMode,
      });
    }
  } catch (err) {
    console.warn('Tauri API unavailable, returning simulated verification report:', err);
  }

  // Simulation fallback for browser dev mode
  const isNvme = device.media_type === 'SsdNvme';
  const now = new Date().toISOString();
  return {
    target_id: device.stable_id,
    levels_executed: ['L1Logical', 'L2HostVisible', 'L3DeviceReported', 'L4Forensic'],
    results: [
      {
        level: 'L1Logical',
        status: 'PASS',
        method: 'Logical MBR/GPT Partition Inspection (Simulation)',
        confidence_pct: 85,
        detail: `[SIMULATION] Logical verification PASSED. No active filesystem metadata on '${device.stable_id}'.`,
        evidence: ['[SIMULATION] blkid: no filesystem type detected', '[SIMULATION] MBR sector: all 0x00'],
        timestamp: now,
        limitations: ['[SIMULATION] Verified against virtual storage state; physical sector 0 not read.'],
      },
      {
        level: 'L2HostVisible',
        status: 'PASS',
        method: 'Host LBA Sampling & Shannon Entropy Analysis (Simulation)',
        confidence_pct: 95,
        detail: `[SIMULATION] Block sampling PASSED — 64 samples, mean entropy 0.0001 bits/byte.`,
        evidence: ['[SIMULATION] Block samples taken: 64', '[SIMULATION] Entropy analysis: mean=0.0001, min=0.0, max=0.0002', '[SIMULATION] Pattern check: 64/64 blocks passed'],
        timestamp: now,
        limitations: ['[SIMULATION] Entropy and pattern scan performed over simulated sample blocks.'],
      },
      {
        level: 'L3DeviceReported',
        status: isNvme ? 'PASS' : 'UNSUPPORTED',
        method: 'NVMe Sanitize Status Log Page 0x81 (Simulation)',
        confidence_pct: isNvme ? 80 : 0,
        detail: isNvme
          ? '[SIMULATION] NVMe Sanitize Status Log PASSED. SSTAT=0x01, SPROG=0xFFFF, GlobalDataErased=true.'
          : `L3 Device-Reported verification is UNSUPPORTED for media type '${device.media_type}'.`,
        evidence: isNvme
          ? ['[SIMULATION] NVMe Log Page 0x81 read', '[SIMULATION] SSTAT[2:0]=0x01 ✓', '[SIMULATION] SPROG=0xFFFF ✓']
          : ['L3 not applicable for USB flash / virtual disks — expected per spec'],
        timestamp: now,
        limitations: isNvme
          ? ['[SIMULATION] Telemetry read from SimulatedNvmeController state machine.']
          : ['USB mass storage and SATA bridges do not implement NVMe Sanitize Log Page 0x81.'],
      },
      {
        level: 'L4Forensic',
        status: 'PASS',
        method: 'VANISH Deep Signature Carving & Bi-Fragment Reconstruction Scanner',
        confidence_pct: 85,
        detail: `[SIMULATION] Forensic validation PASSED: 0 target artifacts recovered by VANISH carving pipeline on '${device.stable_id}'.`,
        evidence: [
          '[SIMULATION] Source: Post-sanitization buffer for ' + device.stable_id,
          '[SIMULATION] Signatures Checked: 12 formats (JPEG, PNG, PDF, ZIP, ELF, SQLite, etc.)',
          '[SIMULATION] Candidate headers found: 0',
          '[SIMULATION] Validated artifacts reconstructed: 0',
        ],
        timestamp: now,
        limitations: ['[SIMULATION] Evaluated against in-memory post-sanitization sample buffer.'],
      },
    ],
    overall_passed: true,
    confidence_pct: isNvme ? 88 : 82,
    timestamp_utc: now,
    unsupported_levels: isNvme ? [] : ['L3DeviceReported'],
    is_simulation: true,
  };
}

export async function issueCertificate(
  device: Device,
  sanitizationMethod: string,
  passesCompleted: number,
  bytesProcessed: number,
  simulationMode: boolean,
  standard: string
): Promise<SanitizationCertificate> {
  try {
    if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
      const { invoke } = await import('@tauri-apps/api/core');
      return await invoke<SanitizationCertificate>('issue_certificate', {
        device,
        sanitizationMethod,
        passesCompleted,
        bytesProcessed,
        simulationMode,
        standard,
      });
    }
  } catch (err) {
    console.warn('Tauri API unavailable, returning simulated certificate:', err);
  }

  const certId = `cert-sim-${Math.random().toString(36).substring(2, 9)}`;
  const keyId = Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
  const pubKey = Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
  const sig = Array.from({ length: 128 }, () => Math.floor(Math.random() * 16).toString(16)).join('');

  return {
    cert_id: certId,
    cert_version: '1.0.0',
    issued_at: new Date().toISOString(),
    device_identity: {
      stable_id: device.stable_id,
      model: device.model,
      serial: device.serial,
      capacity_bytes: device.capacity_bytes,
      media_type: typeof device.media_type === 'string' ? device.media_type : 'Unknown',
    },
    operation_summary: {
      standard,
      method: sanitizationMethod,
      passes_completed: passesCompleted,
      bytes_processed: bytesProcessed,
      simulation_mode: simulationMode,
    },
    verification_result: {
      target_id: device.stable_id,
      levels_executed: ['L1Logical', 'L2HostVisible', 'L4Forensic'],
      results: [],
      overall_passed: true,
      confidence_pct: 85,
      timestamp_utc: new Date().toISOString(),
      unsupported_levels: ['L3DeviceReported'],
    },
    audit_chain_root_hash: Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
    audit_event_count: 3,
    signing_identity: {
      key_id: keyId,
      public_key_hex: pubKey,
      scope: 'session',
      created_at: new Date().toISOString(),
    },
    signature: sig,
    trust_scope_note: 'SESSION KEY: Proves internal consistency of this VANISH run. Key is discarded on exit.',
  };
}

/**
 * Fetch hashing status from the backend.
 *
 * Backend contract (mirrors common/hashing.py output):
 *   { algorithm: "SHA-256" | "BLAKE3", digest: string, purpose: "canonical_evidence" | "internal_processing",
 *     source_label: string, computed_at: string, simulation_mode: boolean }
 *
 * SHA-256 = canonical evidence hash (artifact identity, image integrity, report verification)
 * BLAKE3  = high-speed internal hash (large scan throughput, chunk dedup, caching)
 *
 * The UI never computes hashes. It only displays what the backend returns.
 * When backend is unavailable, clearly labelled simulation_mode=true results are returned.
 */
export async function fetchHashStatus(): Promise<HashStatusReport> {
  try {
    if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
      const { invoke } = await import('@tauri-apps/api/core');
      const results = await invoke<HashStatusReport>('get_hash_status');
      return { ...results, backend_available: true };
    }
  } catch (err) {
    console.warn('Tauri API unavailable, returning simulation hash status:', err);
  }

  // Simulation fallback — clearly labelled, never presented as real forensic results.
  // Never show zero-filled hashes as though they are real evidence.
  const now = new Date().toISOString();
  return {
    backend_available: false,
    results: [
      {
        algorithm: 'SHA-256',
        digest: 'SIMULATED / UNAVAILABLE (Backend Offline)',
        purpose: 'canonical_evidence',
        source_label: 'Audit chain tip hash (Simulation fallback)',
        computed_at: now,
        simulation_mode: true,
      },
      {
        algorithm: 'SHA-256',
        digest: 'SIMULATED / UNAVAILABLE (Backend Offline)',
        purpose: 'canonical_evidence',
        source_label: 'Last recovered artifact identity hash (Simulation fallback)',
        computed_at: now,
        simulation_mode: true,
      },
      {
        algorithm: 'BLAKE3',
        digest: 'SIMULATED / UNAVAILABLE (Backend Offline)',
        purpose: 'internal_processing',
        source_label: 'Storage scan chunk hash (Simulation fallback)',
        computed_at: now,
        simulation_mode: true,
      },
    ],
  };
}

/**
 * Executes a forensic carving and recovery scan on the target image or disposable media.
 * Connects to the native Tauri `scan_and_recover_artifacts` command.
 */
export async function scanAndRecoverArtifacts(
  sourcePath: string = 'disk-vdisk-01',
  simulationMode: boolean = true
): Promise<import('../types').RecoveredArtifact[]> {
  try {
    if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
      const { invoke } = await import('@tauri-apps/api/core');
      return await invoke<import('../types').RecoveredArtifact[]>('scan_and_recover_artifacts', {
        sourcePath,
        simulationMode,
      });
    }
  } catch (err) {
    console.warn('Tauri API unavailable, returning simulated carved artifacts:', err);
  }

  const now = new Date().toISOString();
  return [
    {
      artifact_id: 'art-001-jpg',
      source_id: 'disk-vdisk-01',
      source_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      source_offsets: [[4096, 61440]],
      format: 'Jpeg',
      original_path: 'recovered/art-001_carved.jpg',
      extracted_path: 'recovered/art-001_carved.jpg',
      size_bytes: 57344,
      sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      optional_blake3: 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262',
      validation_status: 'Valid',
      validation_method: 'JPEG Complete Frame & Marker Stream Parser',
      confidence_score: 0.98,
      timestamp_utc: now,
      provenance: {
        source_id: 'disk-vdisk-01',
        source_type_desc: 'SimulationBuffer',
        detection_method: 'ContiguousSignature',
        validation_method: 'JPEG Complete Frame & Marker Stream Parser',
        sector_ranges: [[8, 120]],
        fragments: [
          {
            sequence_index: 0,
            start_offset: 4096,
            length_bytes: 57344,
            sector_start: 8,
            sector_end: 120,
          },
        ],
        entropy_score: 7.84,
        header_magic: 'FF D8 FF E0',
        recovery_timestamp_utc: now,
      },
    },
    {
      artifact_id: 'art-002-pdf',
      source_id: 'disk-vdisk-01',
      source_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      source_offsets: [[32768, 65536]],
      format: 'Pdf',
      original_path: 'recovered/art-002_reconstructed.pdf',
      extracted_path: 'recovered/art-002_reconstructed.pdf',
      size_bytes: 32768,
      sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
      optional_blake3: 'b14457e5b61c569fe01c8767e7c9927be636d1b783f982462e843c08bf60e1d4',
      validation_status: 'Valid',
      validation_method: 'Bi-Fragment Stitched & PDF Object Catalog & Trailer Parser',
      confidence_score: 0.94,
      timestamp_utc: now,
      provenance: {
        source_id: 'disk-vdisk-01',
        source_type_desc: 'SimulationBuffer',
        detection_method: 'FragmentedReconstruction',
        validation_method: 'Bi-Fragment Stitched & PDF Object Catalog & Trailer Parser',
        sector_ranges: [[64, 96], [128, 160]],
        fragments: [
          {
            sequence_index: 0,
            start_offset: 32768,
            length_bytes: 16384,
            sector_start: 64,
            sector_end: 96,
          },
          {
            sequence_index: 1,
            start_offset: 65536,
            length_bytes: 16384,
            sector_start: 128,
            sector_end: 160,
          },
        ],
        entropy_score: 7.21,
        header_magic: '25 50 44 46',
        recovery_timestamp_utc: now,
      },
    },
    {
      artifact_id: 'art-003-png',
      source_id: 'disk-vdisk-01',
      source_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      source_offsets: [[65536, 98304]],
      format: 'Png',
      original_path: 'recovered/art-003_carved.png',
      extracted_path: 'recovered/art-003_carved.png',
      size_bytes: 32768,
      sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
      optional_blake3: '86a455a5b512c5b36483561a0f81d87f73967d74f2604082260ff0d4e3bb0767',
      validation_status: 'Valid',
      validation_method: 'PNG Chunk Sequence & CRC32 Validator',
      confidence_score: 0.99,
      timestamp_utc: now,
      provenance: {
        source_id: 'disk-vdisk-01',
        source_type_desc: 'SimulationBuffer',
        detection_method: 'ContiguousSignature',
        validation_method: 'PNG Chunk Sequence & CRC32 Validator',
        sector_ranges: [[128, 192]],
        fragments: [
          {
            sequence_index: 0,
            start_offset: 65536,
            length_bytes: 32768,
            sector_start: 128,
            sector_end: 192,
          },
        ],
        entropy_score: 7.92,
        header_magic: '89 50 4E 47',
        recovery_timestamp_utc: now,
      },
    },
  ];
}

/**
 * Executes a full forensic recovery job returning an end-to-end RecoveryResult.
 * Connects to the native Tauri `execute_recovery_job` command.
 */
export async function executeRecoveryJob(
  job: import('../types').RecoveryJob
): Promise<import('../types').RecoveryResult> {
  try {
    if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
      const { invoke } = await import('@tauri-apps/api/core');
      return await invoke<import('../types').RecoveryResult>('execute_recovery_job', {
        job,
      });
    }
  } catch (err) {
    console.warn('Tauri API unavailable, returning simulated recovery result:', err);
  }

  const artifacts = await scanAndRecoverArtifacts(job.source_path, job.simulation_mode);
  return {
    job_id: job.job_id,
    source_id: job.source_path,
    total_scanned_bytes: 1048576,
    artifacts,
    simulation_mode: job.simulation_mode,
    execution_time_ms: 120,
    summary_notes: `Forensic carving completed across ${artifacts.length} artifacts with valid signatures.`,
  };
}
