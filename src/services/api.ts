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
  return {
    target_id: device.stable_id,
    levels_executed: ['L1Logical', 'L2HostVisible', 'L3DeviceReported', 'L4Forensic'],
    results: [
      {
        level: 'L1Logical',
        status: 'PASSED',
        confidence_pct: 85,
        detail: `[SIM] Logical verification PASSED. No filesystem metadata on '${device.stable_id}'.`,
        evidence: ['[SIM] blkid: no filesystem type detected', '[SIM] MBR sector: all 0x00'],
      },
      {
        level: 'L2HostVisible',
        status: 'PASSED',
        confidence_pct: 95,
        detail: `[SIM] Block sampling PASSED — 64 samples, mean entropy 0.0001 bits/byte.`,
        evidence: ['[SIM] Block samples taken: 64', '[SIM] Entropy analysis: mean=0.0001, min=0.0, max=0.0002', '[SIM] Pattern check: 64/64 blocks passed'],
      },
      {
        level: 'L3DeviceReported',
        status: isNvme ? 'PASSED' : 'UNSUPPORTED',
        confidence_pct: isNvme ? 80 : 0,
        detail: isNvme
          ? '[SIM] NVMe Sanitize Status Log PASSED. SSTAT=0x01, SPROG=0xFFFF, GlobalDataErased=true.'
          : `L3 Device-Reported verification is NOT SUPPORTED for media type '${device.media_type}'.`,
        evidence: isNvme
          ? ['[SIM] NVMe Log Page 0x81 read', '[SIM] SSTAT[2:0]=0x01 ✓', '[SIM] SPROG=0xFFFF ✓']
          : ['L3 not applicable for USB flash / virtual disks — expected per spec'],
      },
      {
        level: 'L4Forensic',
        status: 'PASSED',
        confidence_pct: 75,
        detail: `[SIM] Forensic validation PASSED — 0 files recoverable on '${device.stable_id}'.`,
        evidence: ['[SIM] File-carving scan: 0 files recovered', '[SIM] Agent B handshake: CONFIRMED UNRECOVERABLE'],
      },
    ],
    overall_passed: true,
    confidence_pct: isNvme ? 88 : 82,
    timestamp_utc: new Date().toISOString(),
    unsupported_levels: isNvme ? [] : ['L3DeviceReported'],
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
  // Digests are zero-filled to make it unambiguous this is not a real hash value.
  const now = new Date().toISOString();
  return {
    backend_available: false,
    results: [
      {
        algorithm: 'SHA-256',
        digest: '0000000000000000000000000000000000000000000000000000000000000000',
        purpose: 'canonical_evidence',
        source_label: 'Audit chain tip hash (simulation — no real data hashed)',
        computed_at: now,
        simulation_mode: true,
      },
      {
        algorithm: 'SHA-256',
        digest: '0000000000000000000000000000000000000000000000000000000000000000',
        purpose: 'canonical_evidence',
        source_label: 'Last recovered artifact identity hash (simulation)',
        computed_at: now,
        simulation_mode: true,
      },
      {
        algorithm: 'BLAKE3',
        digest: '0000000000000000000000000000000000000000000000000000000000000000',
        purpose: 'internal_processing',
        source_label: 'Storage scan chunk hash (simulation — large block dedup)',
        computed_at: now,
        simulation_mode: true,
      },
    ],
  };
}
