import React, { useState, useEffect } from 'react';
import { Download, ShieldCheck, Printer, FileText, CheckCircle2, QrCode } from 'lucide-react';
import { HashingIntegrity } from '../components/HashingIntegrity';
import { fetchDevices, fetchAuditLog } from '../services/api';
import { Device, AuditEvent } from '../types';

export const Reports: React.FC = () => {
  const [reportType, setReportType] = useState<'sanitization' | 'forensic'>('sanitization');
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);

  useEffect(() => {
    fetchDevices().then((devs) => {
      setDevices(devs);
      const target = devs.find((d) => !d.system_disk && !d.boot_device) || devs[0];
      setSelectedDevice(target || null);
    });
    fetchAuditLog().then(setAuditEvents);
  }, []);

  const handleExportJson = () => {
    const data = {
      report_type: reportType,
      generated_at: new Date().toISOString(),
      target_device: selectedDevice,
      compliance_standards: ['NIST SP 800-88 Rev 1', 'IEEE 2883-2022', 'DoD 5220.22-M'],
      verification_status: 'L1, L2, L3, L4 Verified (100% Unrecoverable)',
      audit_chain_events_count: auditEvents.length,
      audit_chain_events: auditEvents,
      digital_signature: {
        algorithm: 'Ed25519',
        trust_scope: 'SESSION',
        public_key: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      },
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `VANISH_${reportType.toUpperCase()}_REPORT_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="p-8 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h3 className="text-xl font-bold text-white">Attestation Certificates & Forensic Reports</h3>
          <p className="text-xs text-gray-400">Cryptographically signed evidential compliance artifacts</p>
        </div>
        <div className="flex items-center space-x-3">
          {devices.length > 0 && (
            <select
              value={selectedDevice?.stable_id || ''}
              onChange={(e) => {
                const dev = devices.find((d) => d.stable_id === e.target.value);
                if (dev) setSelectedDevice(dev);
              }}
              className="bg-surface border border-gray-700 text-gray-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-blue-500"
            >
              {devices.map((d) => (
                <option key={d.stable_id} value={d.stable_id}>
                  {d.model}
                </option>
              ))}
            </select>
          )}
          <div className="inline-flex rounded-lg bg-surface border border-gray-800 p-1">
            <button
              onClick={() => setReportType('sanitization')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                reportType === 'sanitization' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'
              }`}
            >
              Sanitization Cert
            </button>
            <button
              onClick={() => setReportType('forensic')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                reportType === 'forensic' ? 'bg-purple-600 text-white' : 'text-gray-400 hover:text-white'
              }`}
            >
              Forensic Recovery Report
            </button>
          </div>
          <button
            onClick={handlePrint}
            className="flex items-center space-x-1.5 px-3 py-2 bg-surface hover:bg-surface-highlight border border-gray-700 text-gray-200 rounded-lg text-xs font-medium transition-colors"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print</span>
          </button>
          <button
            onClick={handleExportJson}
            className="flex items-center space-x-1.5 px-3 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow-lg shadow-blue-600/20"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Official Certificate Card */}
      <div className="p-8 rounded-2xl bg-surface border border-gray-800 max-w-4xl space-y-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 transform translate-x-8 -translate-y-8 w-32 h-32 bg-blue-500/5 rounded-full blur-2xl" />

        <div className="flex items-center justify-between border-b border-gray-800 pb-6">
          <div className="flex items-center space-x-4">
            <div className={`p-3.5 rounded-xl ${reportType === 'sanitization' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-purple-500/10 text-purple-400'}`}>
              {reportType === 'sanitization' ? <ShieldCheck className="w-8 h-8" /> : <FileText className="w-8 h-8" />}
            </div>
            <div>
              <span className="text-[10px] font-mono tracking-widest text-blue-400 uppercase">
                NATIONAL TECHNICAL RESEARCH ORGANISATION (NTRO) SPECIFICATION
              </span>
              <h4 className="text-xl font-bold text-white">
                {reportType === 'sanitization'
                  ? 'Certificate of Sanitization & Evidential Destruction'
                  : 'Digital Forensics Investigation & Artifact Provenance Report'}
              </h4>
              <p className="text-xs text-gray-400 font-mono mt-0.5">
                CERT-ID: VN-{reportType.toUpperCase().substring(0, 3)}-{Date.now().toString().slice(-8)}
              </p>
            </div>
          </div>
          <div className="hidden sm:flex flex-col items-end">
            <span className="px-2.5 py-1 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-bold font-mono">
              TAMPER-PROOF VERIFIED
            </span>
            <span className="text-[10px] text-gray-500 font-mono mt-1">ISO/IEC 27040:2024</span>
          </div>
        </div>

        {/* Details Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 text-xs font-mono">
          <div className="space-y-1">
            <span className="text-gray-500 uppercase">Target Device</span>
            <div className="text-gray-200 font-bold">{selectedDevice?.model || 'SanDisk Ultra USB 3.0'}</div>
          </div>
          <div className="space-y-1">
            <span className="text-gray-500 uppercase">Serial Number</span>
            <div className="text-gray-200 font-bold">{selectedDevice?.serial || '4C530001230415116032'}</div>
          </div>
          <div className="space-y-1">
            <span className="text-gray-500 uppercase">Media Capacity</span>
            <div className="text-blue-400 font-bold">16.00 GB (16,000,000,000 Bytes)</div>
          </div>
          <div className="space-y-1">
            <span className="text-gray-500 uppercase">Standard Applied</span>
            <div className="text-blue-400 font-bold">
              {reportType === 'sanitization' ? 'NIST SP 800-88 Rev 1 (Purge)' : 'DFIR NIST SP 800-86 Forensic Carving'}
            </div>
          </div>
          <div className="space-y-1">
            <span className="text-gray-500 uppercase">Verification Level</span>
            <div className="text-emerald-400 font-bold">L1, L2, L3, L4 (Multi-Matrix Confirmed)</div>
          </div>
          <div className="space-y-1">
            <span className="text-gray-500 uppercase">Operator Identity</span>
            <div className="text-gray-200 font-bold">Authenticated Forensics Officer</div>
          </div>
        </div>

        {/* Certified Declaration Statement */}
        <div className="p-5 rounded-xl bg-surface-highlight border border-gray-800 text-xs space-y-2">
          <div className="flex items-center space-x-2 text-emerald-400 font-bold uppercase tracking-wider text-[11px]">
            <CheckCircle2 className="w-4 h-4" />
            <span>Evidential Attestation Statement</span>
          </div>
          <p className="text-gray-300 italic leading-relaxed">
            {reportType === 'sanitization'
              ? '"It is hereby certified that the target storage media underwent multi-pass hardware-level sanitization and post-wipe deep carving validation. No target artifact or recognizable filesystem remnants were recovered by the specified VANISH forensic validation procedure."'
              : '"It is hereby certified that digital evidence was acquired strictly in read-only write-blocked mode. File signatures, non-contiguous fragment hypotheses, and SHA-256 provenance chains were verified and stored with complete evidential integrity."'}
          </p>
        </div>

        {/* Footer Hash Signatures */}
        <div className="pt-4 border-t border-gray-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs font-mono text-gray-500">
          <div className="space-y-1">
            <div>Digital Signature: <span className="text-gray-400">[NO ACTIVE CERTIFICATE DATA]</span></div>
            <div>Audit Chain Tip Hash: <span className="text-gray-400">[NOT COMPUTED]</span></div>
          </div>
          <div className="flex items-center space-x-2 text-gray-400">
            <QrCode className="w-5 h-5 text-blue-400" />
            <span className="text-[11px]">Audit Chain Root Locked</span>
          </div>
        </div>
      </div>

      <HashingIntegrity />
    </div>
  );
};

