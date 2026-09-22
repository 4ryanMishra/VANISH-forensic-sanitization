import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ArrowRight,
  Cpu,
  RefreshCw,
  HardDrive,
  Lock,
  ScrollText,
  Clock
} from 'lucide-react';
import { PageId } from '../components/Sidebar';
import { fetchDevices, fetchAuditLog } from '../services/api';
import { Device, AuditEvent } from '../types';

interface DashboardProps {
  onNavigate: (page: PageId) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ onNavigate }) => {
  const [devices, setDevices] = useState<Device[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  const loadData = async () => {
    setLoading(true);
    const [devs, logs] = await Promise.all([fetchDevices(), fetchAuditLog()]);
    setDevices(devs);
    setAuditEvents(logs);
    setLoading(false);
  };

  useEffect(() => {
    loadData();
  }, []);

  const systemDisks = devices.filter((d) => d.system_disk || d.boot_device);
  const disposableTargets = devices.filter((d) => !d.system_disk && !d.boot_device);
  const activeTarget = disposableTargets.length > 0 ? disposableTargets[0] : devices[0] || null;

  return (
    <div className="p-8 space-y-8 font-sans max-w-7xl mx-auto">
      {/* ── TOP OPERATIONAL CONTEXT BANNER ─────────────────────────────────── */}
      <div className="bg-surface border border-border rounded-lg p-6 shadow-subtle space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-border pb-5">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className="w-2 h-2 rounded-full bg-verified animate-pulse" />
              <span className="text-[11px] font-mono uppercase tracking-widest text-charcoal-muted font-semibold">
                Workstation Armed & Operational
              </span>
            </div>
            <h2 className="text-xl font-bold text-charcoal tracking-tight font-sans">
              VANISH Forensic Sanitization & Recovery Console
            </h2>
            <p className="text-xs text-charcoal-secondary">
              National Technical Research Organisation (NTRO) Specification Compliance · Native Win32 Raw Storage Stack
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={loadData}
              disabled={loading}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 bg-surface-subtle hover:bg-surface-hover text-xs font-mono text-charcoal-secondary border border-border rounded transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>Rescan Hardware Bus</span>
            </button>
            <button
              onClick={() => onNavigate('forensics')}
              className="inline-flex items-center space-x-1.5 px-4 py-1.5 bg-charcoal hover:bg-charcoal-secondary text-white text-xs font-semibold rounded shadow-subtle transition-colors"
            >
              <span>Launch Evidence Scanner</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Primary Target Strip */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div className="p-3.5 bg-surface-subtle/80 rounded border border-border space-y-1">
            <div className="text-[10px] font-mono uppercase text-charcoal-muted font-semibold">Primary Target Media</div>
            <div className="font-semibold text-charcoal text-sm truncate font-sans">
              {activeTarget ? activeTarget.model : 'Scanning bus...'}
            </div>
            <div className="text-[11px] font-mono text-charcoal-secondary truncate">
              {activeTarget ? activeTarget.path : '—'} · {activeTarget ? (activeTarget.capacity_bytes / (1024 * 1024 * 1024)).toFixed(2) : 0} GiB
            </div>
          </div>

          <div className="p-3.5 bg-surface-subtle/80 rounded border border-border space-y-1">
            <div className="text-[10px] font-mono uppercase text-charcoal-muted font-semibold">Invariant Safety Gate</div>
            <div className="font-semibold text-verified-dark text-sm flex items-center space-x-1.5 font-sans">
              <ShieldCheck className="w-4 h-4 text-verified" />
              <span>{systemDisks.length} System Disks Protected</span>
            </div>
            <div className="text-[11px] font-mono text-charcoal-secondary">
              Boot volume write locks active
            </div>
          </div>

          <div className="p-3.5 bg-surface-subtle/80 rounded border border-border space-y-1">
            <div className="text-[10px] font-mono uppercase text-charcoal-muted font-semibold">Execution Mode</div>
            <div className="font-semibold text-charcoal text-sm flex items-center space-x-1.5 font-sans">
              <Cpu className="w-4 h-4 text-telemetry" />
              <span>{devices.some((d) => !d.is_simulated) ? 'Physical Raw Hardware' : 'Virtual Sandbox'}</span>
            </div>
            <div className="text-[11px] font-mono text-charcoal-secondary">
              L1–L4 Multi-Level Matrix
            </div>
          </div>

          <div className="p-3.5 bg-surface-subtle/80 rounded border border-border space-y-1">
            <div className="text-[10px] font-mono uppercase text-charcoal-muted font-semibold">Audit Ledger Status</div>
            <div className="font-semibold text-charcoal text-sm font-sans">
              {auditEvents.length} Events Linked
            </div>
            <div className="text-[11px] font-mono text-charcoal-secondary truncate">
              Tip: {auditEvents.length > 0 ? auditEvents[auditEvents.length - 1].current_event_hash.substring(0, 16) + '...' : 'Genesis Locked'}
            </div>
          </div>
        </div>
      </div>

      {/* ── THE VANISH OPERATIONAL LIFECYCLE ───────────────────────────────── */}
      <div className="bg-surface border border-border rounded-lg p-6 space-y-5 shadow-subtle">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div>
            <h3 className="text-sm font-semibold text-charcoal uppercase tracking-wider font-mono">
              Investigation & Sanitization Lifecycle
            </h3>
            <p className="text-xs text-charcoal-muted">Sequential evidence and assurance workflow</p>
          </div>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-surface-subtle border border-border text-charcoal-secondary">
            NIST SP 800-88 Rev 1 / IEEE 2883-2022
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-6 gap-3">
          {/* Stage 1 */}
          <div
            onClick={() => onNavigate('forensics')}
            className="p-4 rounded border border-border hover:border-forensic-border hover:bg-forensic-surface/30 cursor-pointer transition-all space-y-2"
          >
            <div className="flex justify-between items-center text-[10px] font-mono font-semibold text-charcoal-muted">
              <span>STAGE 01</span>
              <span className="text-vermilion">VULNERABILITY</span>
            </div>
            <div className="font-semibold text-xs text-charcoal">Normal Deletion</div>
            <p className="text-[11px] text-charcoal-secondary leading-snug">
              OS file deletion only clears index table pointers; raw sector bytes remain intact.
            </p>
          </div>

          {/* Stage 2 */}
          <div
            onClick={() => onNavigate('forensics')}
            className="p-4 rounded border border-forensic-border bg-forensic-surface/40 hover:bg-forensic-surface/70 cursor-pointer transition-all space-y-2"
          >
            <div className="flex justify-between items-center text-[10px] font-mono font-semibold text-forensic">
              <span>STAGE 02</span>
              <span className="px-1 bg-forensic text-white rounded text-[9px]">CARVE</span>
            </div>
            <div className="font-semibold text-xs text-charcoal">Forensic Carving</div>
            <p className="text-[11px] text-charcoal-secondary leading-snug">
              Read-only sector scan reconstructs contiguous & fragmented files with SHA-256 evidence.
            </p>
          </div>

          {/* Stage 3 */}
          <div
            onClick={() => onNavigate('devices')}
            className="p-4 rounded border border-border hover:border-telemetry-border hover:bg-telemetry-surface/30 cursor-pointer transition-all space-y-2"
          >
            <div className="flex justify-between items-center text-[10px] font-mono font-semibold text-charcoal-muted">
              <span>STAGE 03</span>
              <span className="text-telemetry">PROBE</span>
            </div>
            <div className="font-semibold text-xs text-charcoal">Media Capability</div>
            <p className="text-[11px] text-charcoal-secondary leading-snug">
              Identifies hardware NVMe sanitize, ATA secure erase, or host-block overwrite limits.
            </p>
          </div>

          {/* Stage 4 */}
          <div
            onClick={() => onNavigate('sanitization')}
            className="p-4 rounded border border-vermilion-border bg-vermilion-surface/40 hover:bg-vermilion-surface/70 cursor-pointer transition-all space-y-2"
          >
            <div className="flex justify-between items-center text-[10px] font-mono font-semibold text-vermilion">
              <span>STAGE 04</span>
              <span className="px-1 bg-vermilion text-white rounded text-[9px]">SANITIZE</span>
            </div>
            <div className="font-semibold text-xs text-charcoal">Secure Sanitization</div>
            <p className="text-[11px] text-charcoal-secondary leading-snug">
              Two-stage invariant safety gate authorizes multi-pass raw sector overwrite.
            </p>
          </div>

          {/* Stage 5 */}
          <div
            onClick={() => onNavigate('verification')}
            className="p-4 rounded border border-verified-border bg-verified-surface/40 hover:bg-verified-surface/70 cursor-pointer transition-all space-y-2"
          >
            <div className="flex justify-between items-center text-[10px] font-mono font-semibold text-verified-dark">
              <span>STAGE 05</span>
              <span className="px-1 bg-verified text-white rounded text-[9px]">VERIFY</span>
            </div>
            <div className="font-semibold text-xs text-charcoal">L1–L4 Matrix Proof</div>
            <p className="text-[11px] text-charcoal-secondary leading-snug">
              Evaluates MBR absence, Shannon entropy profile, and deep re-carving absence test.
            </p>
          </div>

          {/* Stage 6 */}
          <div
            onClick={() => onNavigate('reports')}
            className="p-4 rounded border border-border hover:border-charcoal hover:bg-surface-subtle cursor-pointer transition-all space-y-2"
          >
            <div className="flex justify-between items-center text-[10px] font-mono font-semibold text-charcoal-muted">
              <span>STAGE 06</span>
              <span className="text-charcoal font-bold">ATTEST</span>
            </div>
            <div className="font-semibold text-xs text-charcoal">Signed Attestation</div>
            <p className="text-[11px] text-charcoal-secondary leading-snug">
              Issues Ed25519-signed certificate anchoring the complete SHA-256 audit chain.
            </p>
          </div>
        </div>
      </div>

      {/* ── SPLIT PANEL: HARDWARE BUS & AUDIT LEDGER ───────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Connected Media Inventory */}
        <div className="bg-surface border border-border rounded-lg p-6 space-y-4 shadow-subtle">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center space-x-2">
              <HardDrive className="w-4 h-4 text-charcoal" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-charcoal font-mono">
                Enumerated Storage Media ({devices.length})
              </h3>
            </div>
            <button
              onClick={() => onNavigate('devices')}
              className="text-xs font-mono text-charcoal-muted hover:text-charcoal flex items-center space-x-1"
            >
              <span>Full Manager</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-2.5">
            {devices.map((d) => {
              const isProtected = d.system_disk || d.boot_device;
              return (
                <div
                  key={d.stable_id}
                  className={`p-3.5 rounded border transition-all text-xs font-mono flex items-center justify-between ${
                    isProtected
                      ? 'bg-vermilion-surface/40 border-vermilion-border'
                      : 'bg-surface-subtle border-border hover:border-border-strong'
                  }`}
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-semibold text-charcoal font-sans text-xs">{d.model}</span>
                      {d.is_simulated && (
                        <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-amber-surface text-amber-dark border border-amber-border">
                          SIM
                        </span>
                      )}
                    </div>
                    <div className="text-[11px] text-charcoal-muted">
                      {d.path} · S/N: {d.serial} · {(d.capacity_bytes / (1024 * 1024 * 1024)).toFixed(2)} GiB
                    </div>
                  </div>

                  <div>
                    {isProtected ? (
                      <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-vermilion-surface text-vermilion-dark font-semibold text-[11px] border border-vermilion-border">
                        <Lock className="w-3 h-3" />
                        <span>WRITE-LOCKED</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-verified-surface text-verified-dark font-semibold text-[11px] border border-verified-border">
                        <ShieldCheck className="w-3 h-3 text-verified" />
                        <span>ELIGIBLE</span>
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Recent Tamper-Evident Audit Ledger */}
        <div className="bg-surface border border-border rounded-lg p-6 space-y-4 shadow-subtle">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center space-x-2">
              <ScrollText className="w-4 h-4 text-charcoal" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-charcoal font-mono">
                Recent Audit Ledger ({auditEvents.length})
              </h3>
            </div>
            <button
              onClick={() => onNavigate('audit')}
              className="text-xs font-mono text-charcoal-muted hover:text-charcoal flex items-center space-x-1"
            >
              <span>Inspect Chain</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-2.5">
            {auditEvents.slice(-3).reverse().map((evt) => (
              <div
                key={evt.event_id}
                className="p-3.5 rounded bg-surface-subtle border border-border space-y-1.5 text-xs font-mono"
              >
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-charcoal font-sans">{evt.operation}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-verified-surface text-verified-dark border border-verified-border font-bold">
                    {evt.result_status}
                  </span>
                </div>
                <div className="flex items-center justify-between text-[11px] text-charcoal-muted">
                  <span>Target: {evt.target_id}</span>
                  <span className="flex items-center space-x-1">
                    <Clock className="w-3 h-3" />
                    <span>{new Date(evt.timestamp).toLocaleTimeString()}</span>
                  </span>
                </div>
                <div className="text-[10px] text-charcoal-faint truncate pt-0.5">
                  Hash: {evt.current_event_hash}
                </div>
              </div>
            ))}
            {auditEvents.length === 0 && (
              <div className="p-8 text-center text-xs text-charcoal-muted font-mono">
                Genesis block active. Operations will be appended to the SHA-256 chain.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
