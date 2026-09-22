import React, { useState, useEffect } from 'react';
import { Device, VerificationReport, LevelResult, SanitizationCertificate } from '../types';
import { fetchDevices, runVerification, issueCertificate } from '../services/api';
import { ShieldCheck, ShieldX, ShieldAlert, AlertCircle, FileCheck2, Award, ChevronDown, ChevronUp } from 'lucide-react';

const LEVEL_LABELS: Record<string, string> = {
  L1Logical: 'L1 · Logical Filesystem Remnant Scan',
  L2HostVisible: 'L2 · Host-Visible Block Verification',
  L3DeviceReported: 'L3 · Device-Reported NVMe Sanitize Log',
  L4Forensic: 'L4 · Deep Forensic Carving & Reconstruction',
};

const LEVEL_WEIGHTS: Record<string, string> = {
  L1Logical: '15%',
  L2HostVisible: '35%',
  L3DeviceReported: '30%',
  L4Forensic: '20%',
};

function StatusBadge({ status }: { status: string }) {
  const norm = status.toUpperCase();
  const cfg = {
    PASS: { cls: 'bg-verified/10 text-verified border-verified/30', label: 'PASS' },
    PASSED: { cls: 'bg-verified/10 text-verified border-verified/30', label: 'PASS' },
    UNSUPPORTED: { cls: 'bg-surface-elevated text-charcoal/50 border-border', label: 'UNSUPPORTED' },
    NOT_AVAILABLE: { cls: 'bg-amber/10 text-amber border-amber/30', label: 'NOT AVAILABLE' },
    INCONCLUSIVE: { cls: 'bg-telemetry/10 text-telemetry border-telemetry/30', label: 'INCONCLUSIVE' },
    FAIL: { cls: 'bg-vermilion/10 text-vermilion border-vermilion/30', label: 'FAIL' },
    FAILED: { cls: 'bg-vermilion/10 text-vermilion border-vermilion/30', label: 'FAIL' },
    ERROR: { cls: 'bg-vermilion/10 text-vermilion border-vermilion/30', label: 'ERROR' },
  }[norm] ?? { cls: 'bg-surface-elevated text-charcoal/50 border-border', label: status };

  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${cfg.cls}`}>
      {cfg.label}
    </span>
  );
}

function LevelCard({ result }: { result: LevelResult }) {
  const [expanded, setExpanded] = useState(false);
  const norm = result.status.toUpperCase();

  const borderColor = {
    PASS: 'border-verified/30',
    PASSED: 'border-verified/30',
    UNSUPPORTED: 'border-border',
    NOT_AVAILABLE: 'border-amber/30',
    INCONCLUSIVE: 'border-telemetry/30',
    FAIL: 'border-vermilion/30',
    FAILED: 'border-vermilion/30',
    ERROR: 'border-vermilion/30',
  }[norm] ?? 'border-border';

  const Icon = {
    PASS: ShieldCheck,
    PASSED: ShieldCheck,
    UNSUPPORTED: ShieldAlert,
    NOT_AVAILABLE: AlertCircle,
    INCONCLUSIVE: AlertCircle,
    FAIL: ShieldX,
    FAILED: ShieldX,
    ERROR: AlertCircle,
  }[norm] ?? ShieldAlert;

  const iconColor = {
    PASS: 'text-verified',
    PASSED: 'text-verified',
    UNSUPPORTED: 'text-charcoal/40',
    NOT_AVAILABLE: 'text-amber',
    INCONCLUSIVE: 'text-telemetry',
    FAIL: 'text-vermilion',
    FAILED: 'text-vermilion',
    ERROR: 'text-vermilion',
  }[norm] ?? 'text-charcoal/40';

  return (
    <div className={`rounded-xl border ${borderColor} bg-white overflow-hidden shadow-subtle`}>
      <button
        onClick={() => setExpanded((e) => !e)}
        className="w-full p-4 flex items-center justify-between text-left hover:bg-surface-elevated transition-colors"
      >
        <div className="flex items-center space-x-3">
          <Icon className={`w-5 h-5 flex-shrink-0 ${iconColor}`} />
          <div>
            <div className="text-xs font-bold text-charcoal font-mono">
              {LEVEL_LABELS[result.level] ?? result.level}
            </div>
            <div className="text-[11px] text-charcoal/50 mt-0.5 font-mono">
              Weight: {LEVEL_WEIGHTS[result.level] ?? '?'} · Confidence: {result.confidence_pct}%
            </div>
          </div>
        </div>
        <div className="flex items-center space-x-3">
          <StatusBadge status={result.status} />
          {expanded ? (
            <ChevronUp className="w-4 h-4 text-charcoal/40" />
          ) : (
            <ChevronDown className="w-4 h-4 text-charcoal/40" />
          )}
        </div>
      </button>
      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-border bg-surface-elevated/30">
          {result.method && (
            <div className="text-[11px] font-mono text-telemetry mt-3 font-semibold">
              <span className="text-charcoal/50">Method: </span>{result.method}
            </div>
          )}
          <p className="text-xs text-charcoal/80 leading-relaxed font-sans">{result.detail}</p>
          <div className="space-y-1">
            {result.evidence?.map((e, i) => (
              <div key={i} className="text-[11px] font-mono text-charcoal/70 flex items-start space-x-2">
                <span className="text-charcoal/30 select-none">›</span>
                <span>{e}</span>
              </div>
            ))}
          </div>
          {result.limitations && result.limitations.length > 0 && (
            <div className="pt-2 border-t border-border">
              <div className="text-[10px] font-mono font-bold text-amber uppercase tracking-wider mb-1">
                Declared Architectural Limitations:
              </div>
              {result.limitations.map((lim, idx) => (
                <div key={idx} className="text-[11px] text-charcoal/60 font-sans italic flex items-start space-x-1.5">
                  <span className="text-amber font-bold">•</span>
                  <span>{lim}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ConfidenceRing({ pct }: { pct: number }) {
  const r = 36;
  const circ = 2 * Math.PI * r;
  const fill = (pct / 100) * circ;
  const color = pct >= 80 ? '#16A34A' : pct >= 60 ? '#D97706' : '#D9381E';

  return (
    <svg width="96" height="96" viewBox="0 0 96 96" className="rotate-[-90deg]">
      <circle cx="48" cy="48" r={r} fill="none" stroke="#E2E2DC" strokeWidth="8" />
      <circle
        cx="48" cy="48" r={r}
        fill="none"
        stroke={color}
        strokeWidth="8"
        strokeDasharray={`${fill} ${circ - fill}`}
        strokeLinecap="round"
        style={{ transition: 'stroke-dasharray 0.8s ease' }}
      />
      <text
        x="48" y="48"
        textAnchor="middle"
        dominantBaseline="middle"
        fill={color}
        fontSize="16"
        fontWeight="bold"
        className="rotate-[90deg] font-mono"
        transform="rotate(90, 48, 48)"
      >
        {pct}%
      </text>
    </svg>
  );
}

export const Verification: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [method, setMethod] = useState<string>('NvmeSanitizeCryptoErase');
  const [isRunning, setIsRunning] = useState(false);
  const [report, setReport] = useState<VerificationReport | null>(null);
  const [cert, setCert] = useState<SanitizationCertificate | null>(null);
  const [isIssuingCert, setIsIssuingCert] = useState(false);

  useEffect(() => {
    fetchDevices().then((devs) => {
      setDevices(devs);
      const target = devs.find((d) => !d.system_disk && !d.boot_device) ?? devs[0];
      setSelectedDevice(target ?? null);
    });
  }, []);

  const handleRunVerification = async () => {
    if (!selectedDevice) return;
    setIsRunning(true);
    setReport(null);
    setCert(null);
    try {
      const r = await runVerification(selectedDevice, method, selectedDevice.is_simulated);
      setReport(r);
    } finally {
      setIsRunning(false);
    }
  };

  const handleIssueCertificate = async () => {
    if (!selectedDevice || !report) return;
    setIsIssuingCert(true);
    try {
      const c = await issueCertificate(
        selectedDevice,
        method,
        1,
        selectedDevice.capacity_bytes,
        selectedDevice.is_simulated,
        'SinglePassZero'
      );
      setCert(c);
    } finally {
      setIsIssuingCert(false);
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="pb-4 border-b border-border">
        <div className="flex items-center space-x-2">
          <span className="text-[10px] font-mono font-bold tracking-widest text-verified uppercase bg-verified/10 px-2 py-0.5 rounded border border-verified/20">
            VERIFICATION ENGINE
          </span>
          <span className="text-[10px] font-mono text-charcoal/50">L1–L4 HONEST MATRIX</span>
        </div>
        <h2 className="text-xl font-bold text-charcoal tracking-tight mt-1">Multi-Level Verification & Attestation</h2>
        <p className="text-xs text-charcoal/60 mt-0.5">
          Mathematical post-sanitization validation with explicit limitation reporting and Ed25519 evidential signing
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Config panel */}
        <div className="space-y-4">
          <div className="p-5 rounded-xl bg-white border border-border space-y-4 shadow-subtle">
            <h4 className="text-xs font-mono font-bold text-charcoal uppercase tracking-wider">
              Target Device Selection
            </h4>
            <div className="space-y-2">
              {devices.filter((d) => !d.system_disk && !d.boot_device).map((d) => (
                <button
                  key={d.stable_id}
                  onClick={() => setSelectedDevice(d)}
                  className={`w-full text-left p-3 rounded-lg border text-xs transition-all ${
                    selectedDevice?.stable_id === d.stable_id
                      ? 'border-verified bg-verified/5 ring-1 ring-verified/30'
                      : 'border-border hover:border-telemetry/40 bg-white'
                  }`}
                >
                  <div className="font-bold text-charcoal">{d.model}</div>
                  <div className="font-mono text-charcoal/50 mt-0.5">{d.path} · {typeof d.media_type === 'string' ? d.media_type : 'Unknown'}</div>
                </button>
              ))}
            </div>
          </div>

          <div className="p-5 rounded-xl bg-white border border-border space-y-3 shadow-subtle">
            <h4 className="text-xs font-mono font-bold text-charcoal uppercase tracking-wider">
              Executed Sanitization Method
            </h4>
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value)}
              className="w-full bg-white border border-border rounded-lg px-3 py-2 text-xs text-charcoal focus:outline-none focus:border-verified font-mono shadow-subtle"
            >
              <option value="NvmeSanitizeCryptoErase">NVMe Crypto Erase</option>
              <option value="NvmeSanitizeBlockErase">NVMe Block Erase</option>
              <option value="SinglePassZero">Single-Pass Zero Fill</option>
              <option value="SinglePassRandom">Single-Pass Random</option>
              <option value="Dod522022M3Pass">DoD 3-Pass Multi-Pattern</option>
            </select>
            <button
              disabled={!selectedDevice || isRunning}
              onClick={handleRunVerification}
              className="w-full py-2.5 rounded-lg bg-charcoal hover:bg-charcoal/90 disabled:opacity-50 text-white text-xs font-semibold shadow-subtle transition-colors"
            >
              {isRunning ? 'Running L1–L4 Scan...' : 'Run Verification Matrix'}
            </button>
          </div>
        </div>

        {/* Results panel */}
        <div className="lg:col-span-2 space-y-4">
          {!report && !isRunning && (
            <div className="flex flex-col items-center justify-center h-64 rounded-xl border border-dashed border-border bg-white text-charcoal/50 shadow-subtle">
              <ShieldCheck className="w-12 h-12 mb-3 opacity-30 text-charcoal" />
              <p className="text-xs font-mono">Select a target storage device and execute verification matrix</p>
            </div>
          )}

          {isRunning && (
            <div className="flex flex-col items-center justify-center h-64 rounded-xl border border-border bg-white space-y-4 shadow-subtle">
              <div className="w-8 h-8 border-2 border-verified border-t-transparent rounded-full animate-spin" />
              <p className="text-xs text-charcoal/60 font-mono">Executing L1 → L2 → L3 → L4 verification levels...</p>
            </div>
          )}

          {report && (
            <>
              {/* Summary header */}
              <div className="p-5 rounded-xl bg-white border border-border flex items-center justify-between shadow-subtle">
                <div>
                  <div className={`text-base font-bold font-mono ${report.overall_passed ? 'text-verified' : 'text-vermilion'}`}>
                    {report.overall_passed ? '✓ Verification Evaluated (Pass)' : '✗ Verification Failed'}
                  </div>
                  <div className="text-xs text-charcoal/60 mt-1 font-mono">
                    Target: <span className="font-bold text-charcoal">{report.target_id}</span>
                    {report.unsupported_levels.length > 0 && (
                      <span className="ml-2 text-charcoal/40">
                        · {report.unsupported_levels.length} level(s) reported UNSUPPORTED
                      </span>
                    )}
                  </div>
                  <div className="text-[10px] text-charcoal/40 mt-1 font-mono">{report.timestamp_utc}</div>
                </div>
                <ConfidenceRing pct={report.confidence_pct} />
              </div>

              {/* Level cards */}
              <div className="space-y-2">
                {report.results.map((r) => (
                  <LevelCard key={r.level} result={r} />
                ))}
              </div>

              {/* Certificate section */}
              <div className="p-5 rounded-xl bg-white border border-border space-y-4 shadow-subtle">
                <div className="flex items-center space-x-2">
                  <Award className="w-5 h-5 text-amber" />
                  <h4 className="text-xs font-mono font-bold text-charcoal uppercase tracking-wider">
                    Evidential Attestation Certificate Issuance
                  </h4>
                </div>
                <p className="text-xs text-charcoal/70 leading-relaxed font-sans">
                  Generates an Ed25519-signed <code className="text-telemetry font-mono font-bold">SanitizationCertificate</code> binding
                  this verification result to the session signing key. A court or auditor can verify authorship using the public key displayed below.
                </p>
                {!cert ? (
                  <button
                    disabled={isIssuingCert}
                    onClick={handleIssueCertificate}
                    className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-amber hover:bg-amber-dark text-white text-xs font-semibold shadow-subtle transition-colors"
                  >
                    <FileCheck2 className="w-4 h-4" />
                    <span>{isIssuingCert ? 'Issuing Certificate...' : 'Issue Signed Certificate'}</span>
                  </button>
                ) : (
                  <div className="space-y-3 text-xs font-mono">
                    <div className="p-4 rounded-lg bg-surface-elevated border border-border space-y-2">
                      <div className="flex justify-between">
                        <span className="text-charcoal/50">Cert ID</span>
                        <span className="text-charcoal font-bold">{cert.cert_id}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-charcoal/50">Version</span>
                        <span className="text-charcoal">{cert.cert_version}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-charcoal/50">Issued At</span>
                        <span className="text-charcoal">{cert.issued_at}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-charcoal/50">Key Scope</span>
                        <span className="text-telemetry font-bold">{cert.signing_identity.scope.toUpperCase()}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-charcoal/50">Public Key</span>
                        <span className="text-charcoal break-all">{cert.signing_identity.public_key_hex.substring(0, 32)}…</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-charcoal/50">Signature</span>
                        <span className="text-verified font-bold">{cert.signature.substring(0, 32)}…</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-charcoal/50">Audit Events</span>
                        <span className="text-charcoal">{cert.audit_event_count}</span>
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-telemetry/5 border border-telemetry/20 text-charcoal/80 leading-relaxed font-sans text-xs">
                      {cert.trust_scope_note}
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
