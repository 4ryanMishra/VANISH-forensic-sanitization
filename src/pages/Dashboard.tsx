import React, { useState, useEffect } from 'react';
import { HardDrive, ShieldCheck, AlertTriangle, ArrowUpRight, Cpu } from 'lucide-react';
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

  useEffect(() => {
    Promise.all([fetchDevices(), fetchAuditLog()]).then(([devs, logs]) => {
      setDevices(devs);
      setAuditEvents(logs);
      setLoading(false);
    });
  }, []);

  const systemDisksCount = devices.filter((d) => d.system_disk || d.boot_device).length;
  const disposableCount = devices.filter((d) => !d.system_disk && !d.boot_device).length;
  const simCount = devices.filter((d) => d.is_simulated).length;
  const isAllSim = simCount > 0 && simCount === devices.length;

  return (
    <div className="p-8 space-y-6">
      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-surface border border-gray-800 shadow-sm">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Detected Targets</span>
            <HardDrive className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-white">
            {loading ? '...' : `${devices.length} Devices`}
          </div>
          <div className="text-xs text-emerald-400 mt-1">
            {loading ? 'Scanning bus...' : `${disposableCount} Disposable / Lab Target${disposableCount !== 1 ? 's' : ''}`}
          </div>
        </div>

        <div className="p-5 rounded-xl bg-surface border border-gray-800 shadow-sm">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Safety Gate</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">
            {systemDisksCount > 0 ? `${systemDisksCount} Protected` : 'Enforced'}
          </div>
          <div className="text-xs text-gray-400 mt-1">
            Host system & boot disks write-locked
          </div>
        </div>

        <div className="p-5 rounded-xl bg-surface border border-gray-800 shadow-sm">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Environment Mode</span>
            <Cpu className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-white">
            {isAllSim ? (
              <span className="text-amber-400 text-lg">SIMULATION</span>
            ) : simCount > 0 ? (
              <span className="text-blue-400 text-lg">HYBRID</span>
            ) : (
              <span className="text-emerald-400 text-lg">REAL HARDWARE</span>
            )}
          </div>
          <div className="text-xs text-purple-400 mt-1">
            L1–L4 Multi-Level Matrix
          </div>
        </div>

        <div className="p-5 rounded-xl bg-surface border border-gray-800 shadow-sm">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Audit Chain</span>
            <ShieldCheck className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-white">
            {auditEvents.length} Events
          </div>
          <div className="text-xs text-indigo-400 mt-1">
            SHA-256 Hash-Linked
          </div>
        </div>
      </div>

      {/* Main Action Banners */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl bg-gradient-to-br from-blue-950/40 via-surface to-surface border border-blue-500/20 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="inline-flex items-center px-2.5 py-1 rounded-full bg-blue-500/10 text-blue-400 text-xs font-medium border border-blue-500/20">
              Sanitization Workflow
            </div>
            <h3 className="text-xl font-bold text-white">Capability-Aware Device Sanitization</h3>
            <p className="text-sm text-gray-400 leading-relaxed">
              Execute NIST SP 800-88 Rev 1, DoD 5220.22-M, and IEEE 2883-2022 compliant sanitization routines tailored specifically to NVMe, SATA SSD, HDD, and flash controller capabilities.
            </p>
          </div>
          <div className="mt-6">
            <button
              onClick={() => onNavigate('sanitization')}
              className="inline-flex items-center space-x-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors shadow-lg shadow-blue-600/20"
            >
              <span>Configure Sanitization Plan</span>
              <ArrowUpRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="p-6 rounded-2xl bg-gradient-to-br from-purple-950/40 via-surface to-surface border border-purple-500/20 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="inline-flex items-center px-2.5 py-1 rounded-full bg-purple-500/10 text-purple-400 text-xs font-medium border border-purple-500/20">
              Forensics & Carving
            </div>
            <h3 className="text-xl font-bold text-white">Deep Forensic Artifact Reconstruction</h3>
            <p className="text-sm text-gray-400 leading-relaxed">
              Read-only evidence acquisition, filesystem slack scanning, magic header carving, and fragmented file graph reconstruction with format-aware decoders.
            </p>
          </div>
          <div className="mt-6">
            <button
              onClick={() => onNavigate('forensics')}
              className="inline-flex items-center space-x-2 px-4 py-2.5 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-sm font-medium transition-colors shadow-lg shadow-purple-600/20"
            >
              <span>Launch Forensic Scanner</span>
              <ArrowUpRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Safety Notice Callout */}
      <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-500/30 flex items-start space-x-3">
        <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
        <div className="text-sm">
          <h4 className="font-semibold text-amber-300">Operational Engineering Protocol Active</h4>
          <p className="text-amber-200/80 text-xs mt-1">
            Host system drives are protected by two-stage invariant safety gates. Destructive sanitization operations require cryptographic confirmation and target serial re-validation.
          </p>
        </div>
      </div>
    </div>
  );
};
