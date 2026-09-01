import { Device, SanitizationPlan, SanitizationStandard, AuditEvent } from '../types';

// Mock data fallback if running in standalone browser without Tauri backend
const MOCK_DEVICES: Device[] = [
  {
    stable_id: 'disk-vdisk-01',
    path: '/dev/loop0',
    model: 'VANISH Virtual Forensic Target',
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
    stable_id: 'disk-sandisk-16g',
    path: '/dev/sdb',
    model: 'SanDisk Ultra USB 3.0',
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
    stable_id: 'disk-nvme-sys',
    path: '/dev/nvme0n1',
    model: 'Samsung SSD 980 PRO 1TB',
    serial: 'S5GXNF0R123456',
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

  return {
    plan_id: `plan-${Math.random().toString(36).substring(2, 9)}`,
    target_id: device.stable_id,
    standard,
    method: device.media_type === 'SsdNvme' ? 'NvmeSanitizeCryptoErase' : 'SimulatedSanitization',
    rationale: `Hardware-aware profile selected for ${typeof device.media_type === 'string' ? device.media_type : 'Device'} under standard ${standard}.`,
    prerequisites: ['Verify target serial number', 'Confirm target is not host boot/system drive'],
    warnings: device.system_disk ? ['PROTECTED SYSTEM DISK: Operation will be rejected by safety gate.'] : [],
    estimated_duration_seconds: 45,
    verification_levels_planned: ['L1_LOGICAL', 'L2_HOST_VISIBLE', 'L4_FORENSIC'],
    simulation_mode: device.media_type === 'VirtualDisk',
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
