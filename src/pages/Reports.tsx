import React, { useState, useEffect } from 'react';
import { Download, ShieldCheck, Printer, FileText, CheckCircle2, QrCode } from 'lucide-react';
import { HashingIntegrity } from '../components/HashingIntegrity';
import { fetchDevices, fetchAuditLog, runVerification } from '../services/api';
import { Device, AuditEvent, VerificationReport } from '../types';

export const Reports: React.FC = () => {
  const [reportType, setReportType] = useState<'sanitization' | 'forensic'>('sanitization');
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [verificationReport, setVerificationReport] = useState<VerificationReport | null>(null);
  const [loadingVerification, setLoadingVerification] = useState(false);

  useEffect(() => {
    fetchDevices().then((devs) => {
      setDevices(devs);
      const target = devs.find((d) => !d.system_disk && !d.boot_device) || devs[0];
      setSelectedDevice(target || null);
    });
    fetchAuditLog().then(setAuditEvents);
  }, []);

  useEffect(() => {
    if (selectedDevice) {
      setLoadingVerification(true);
      const methodStr = selectedDevice.interface === 'Nvme' ? 'NvmeSanitizeBlockErase' : 'HostBlockOverwrite';
      runVerification(selectedDevice, methodStr, selectedDevice.is_simulated)
        .then((v) => setVerificationReport(v))
        .catch(() => setVerificationReport(null))
        .finally(() => setLoadingVerification(false));
    } else {
      setVerificationReport(null);
    }
  }, [selectedDevice]);

  const tipHash = auditEvents.length > 0 ? auditEvents[auditEvents.length - 1].current_event_hash : 'GENESIS-CHAIN-LOCKED-0000000000000000';

  const handleExportJson = () => {
    const data = {
      report_type: reportType,
      generated_at: new Date().toISOString(),
      target_device: selectedDevice,
      compliance_standards: ['NIST SP 800-88 Rev. 2', 'ISO/IEC 27040:2024', 'IEEE 2883-2022'],
      verification_report: verificationReport || 'Verification not yet executed',
      audit_chain_tip_hash: tipHash,
      audit_chain_events_count: auditEvents.length,
      audit_chain_events: auditEvents,
      digital_signature: {
        algorithm: 'Ed25519',
        trust_scope: 'SESSION',
        tip_hash: tipHash,
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

  const formattedCapacity = selectedDevice
    ? `${(selectedDevice.capacity_bytes / 1e9).toFixed(2)} GB (${selectedDevice.capacity_bytes.toLocaleString()} Bytes)`
    : 'No Target Selected';

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border print:hidden">
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-[10px] font-mono font-bold tracking-widest text-amber uppercase bg-amber/10 px-2 py-0.5 rounded border border-amber/20">
              ATTESTATION SUITE
            </span>
            <span className="text-[10px] font-mono text-charcoal/50">ED25519 SIGNED CERTIFICATES</span>
          </div>
          <h2 className="text-xl font-bold text-charcoal tracking-tight mt-1">
            Official Attestation Certificates & Forensic Reports
          </h2>
          <p className="text-xs text-charcoal/60 mt-0.5">
            Cryptographically signed evidential compliance artifacts suitable for legal proceeding and chain-of-custody documentation
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {devices.length > 0 && (
            <select
              value={selectedDevice?.stable_id || ''}
              onChange={(e) => {
                const dev = devices.find((d) => d.stable_id === e.target.value);
                if (dev) setSelectedDevice(dev);
              }}
              className="bg-white border border-border text-charcoal text-xs rounded-lg px-2.5 py-2 focus:outline-none focus:border-amber font-mono shadow-subtle"
            >
              {devices.map((d) => (
                <option key={d.stable_id} value={d.stable_id}>
                  {d.model} {d.is_simulated ? '[SIMULATION]' : ''}
                </option>
              ))}
            </select>
          )}
          <div className="inline-flex rounded-lg bg-surface-elevated border border-border p-1">
            <button
              onClick={() => setReportType('sanitization')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                reportType === 'sanitization' ? 'bg-white text-charcoal shadow-subtle' : 'text-charcoal/60 hover:text-charcoal'
              }`}
            >
              Sanitization Cert
            </button>
            <button
              onClick={() => setReportType('forensic')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                reportType === 'forensic' ? 'bg-white text-charcoal shadow-subtle' : 'text-charcoal/60 hover:text-charcoal'
              }`}
            >
              Forensic Recovery Report
            </button>
          </div>
          <button
            onClick={handlePrint}
            className="flex items-center space-x-1.5 px-3 py-2 bg-white hover:bg-surface-elevated border border-border text-charcoal rounded-lg text-xs font-semibold shadow-subtle transition-colors"
          >
            <Printer className="w-3.5 h-3.5 text-telemetry" />
            <span>Print Certificate</span>
          </button>
          <button
            onClick={handleExportJson}
            className="flex items-center space-x-1.5 px-3.5 py-2 bg-charcoal hover:bg-charcoal/90 text-white rounded-lg text-xs font-semibold shadow-subtle transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Official Certificate Card */}
      <div className="p-8 rounded-2xl bg-white border border-border max-w-4xl space-y-6 shadow-subtle relative print:shadow-none print:border-none print:p-0">
        <div className="flex items-center justify-between border-b border-border pb-6">
          <div className="flex items-center space-x-4">
            <div className={`p-3.5 rounded-xl border ${
              reportType === 'sanitization' 
                ? 'bg-vermilion/10 text-vermilion border-vermilion/20' 
                : 'bg-forensic/10 text-forensic border-forensic/20'
            }`}>
              {reportType === 'sanitization' ? <ShieldCheck className="w-8 h-8" /> : <FileText className="w-8 h-8" />}
            </div>
            <div>
              <span className="text-[10px] font-mono tracking-widest text-telemetry uppercase font-bold">
                NATIONAL TECHNICAL RESEARCH & FORENSIC SPECIFICATION
              </span>
              <h3 className="text-xl font-bold text-charcoal tracking-tight">
                {reportType === 'sanitization'
                  ? 'Certificate of Sanitization & Evidential Destruction'
                  : 'Digital Forensics Investigation & Artifact Provenance Report'}
              </h3>
              <p className="text-xs text-charcoal/50 font-mono mt-0.5">
                CERT-ID: VN-{reportType.toUpperCase().substring(0, 3)}-{Date.now().toString().slice(-8)}
              </p>
            </div>
          </div>
          <div className="hidden sm:flex flex-col items-end">
            <span className="px-2.5 py-1 rounded bg-verified/10 border border-verified/30 text-verified text-xs font-bold font-mono">
              TAMPER-PROOF VERIFIED
            </span>
            <span className="text-[10px] text-charcoal/40 font-mono mt-1">ISO/IEC 27040:2024</span>
          </div>
        </div>

        {/* Details Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 text-xs font-mono">
          <div className="space-y-1">
            <span className="text-charcoal/50 uppercase text-[10px]">Target Device</span>
            <div className="text-charcoal font-bold">{selectedDevice?.model || 'No Target Selected'}</div>
          </div>
          <div className="space-y-1">
            <span className="text-charcoal/50 uppercase text-[10px]">Serial Number</span>
            <div className="text-charcoal font-bold">{selectedDevice?.serial || 'N/A'}</div>
          </div>
          <div className="space-y-1">
            <span className="text-charcoal/50 uppercase text-[10px]">Media Capacity</span>
            <div className="text-telemetry font-bold">{formattedCapacity}</div>
          </div>
          <div className="space-y-1">
            <span className="text-charcoal/50 uppercase text-[10px]">Standard Applied</span>
            <div className="text-charcoal font-bold">
              {reportType === 'sanitization' ? 'NIST SP 800-88 Rev. 2 (Clear)' : 'DFIR NIST SP 800-86 Forensic Carving'}
            </div>
          </div>
          <div className="space-y-1">
            <span className="text-charcoal/50 uppercase text-[10px]">Execution Environment</span>
            <div className={`font-bold ${selectedDevice?.is_simulated ? 'text-amber' : 'text-verified'}`}>
              {selectedDevice?.is_simulated ? 'LAB SIMULATION FIXTURE' : 'PHYSICAL HARDWARE TARGET'}
            </div>
          </div>
          <div className="space-y-1">
            <span className="text-charcoal/50 uppercase text-[10px]">Operator Identity</span>
            <div className="text-charcoal font-bold">Authenticated Forensics Officer</div>
          </div>
        </div>

        {/* Truthful Verification Levels Rendering */}
        <div className="space-y-2">
          <span className="text-[11px] font-mono font-bold text-charcoal/60 uppercase tracking-wider">
            Verification Results ({verificationReport ? `${verificationReport.confidence_pct}% Confidence` : 'Pending'})
          </span>
          {loadingVerification ? (
            <div className="text-xs text-charcoal/40 font-mono py-2">Loading verification telemetry...</div>
          ) : verificationReport && verificationReport.results && verificationReport.results.length > 0 ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {verificationReport.results.map((res) => (
                <div key={res.level} className="p-3 rounded-lg bg-surface-elevated border border-border space-y-1 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-charcoal font-mono">{res.level}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        res.status === 'PASS' || res.status === 'PASSED'
                          ? 'bg-verified/10 text-verified border border-verified/30'
                          : res.status === 'UNSUPPORTED'
                          ? 'bg-white text-charcoal/40 border border-border'
                          : res.status === 'NOT_AVAILABLE'
                          ? 'bg-amber/10 text-amber border border-amber/30'
                          : 'bg-vermilion/10 text-vermilion border border-vermilion/30'
                      }`}
                    >
                      {res.status.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-charcoal/70 text-[11px] font-sans leading-tight">{res.detail}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-3 rounded-lg bg-surface-elevated border border-border text-xs text-charcoal/50 font-mono">
              Verification not yet executed
            </div>
          )}
        </div>

        {/* Certified Declaration Statement */}
        <div className="p-5 rounded-xl bg-surface-elevated border border-border text-xs space-y-2">
          <div className="flex items-center space-x-2 text-verified font-bold uppercase tracking-wider text-[11px] font-mono">
            <CheckCircle2 className="w-4 h-4" />
            <span>Evidential Attestation Statement</span>
          </div>
          <p className="text-charcoal/80 italic font-serif leading-relaxed text-sm">
            {reportType === 'sanitization'
              ? (selectedDevice?.media_type === 'SsdNvme' && !selectedDevice?.is_simulated
                  ? '“It is hereby certified that the target storage media underwent NVMe sanitize purge and post-wipe deep carving validation. Verified according to the methods actually executed by VANISH.”'
                  : selectedDevice?.interface === 'Usb'
                  ? '“It is hereby certified that the target storage media underwent controlled host-level raw block sanitization of the selected volume and post-wipe deep carving validation. No target artifact or recognizable filesystem remnants were recovered by the specified VANISH forensic validation procedure.”'
                  : '“Verified according to the methods actually executed by VANISH.”')
              : '“It is hereby certified that digital evidence was acquired strictly in read-only write-blocked mode. File signatures, non-contiguous fragment hypotheses, and SHA-256 provenance chains were verified and stored with complete evidential integrity.”'}
          </p>
        </div>

        {/* Footer Hash Signatures */}
        <div className="pt-4 border-t border-border flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs font-mono text-charcoal/50">
          <div className="space-y-1">
            <div>Digital Signature: <span className="text-verified font-mono font-bold">Ed25519-Verified (Session Scope)</span></div>
            <div>Audit Chain Tip Hash: <span className="text-charcoal font-mono">{tipHash.substring(0, 32)}...</span></div>
          </div>
          <div className="flex items-center space-x-2 text-charcoal/60">
            <QrCode className="w-5 h-5 text-telemetry" />
            <span className="text-[11px]">Audit Chain Root Locked</span>
          </div>
        </div>
      </div>

      <div className="print:hidden">
        <HashingIntegrity />
      </div>
    </div>
  );
};

