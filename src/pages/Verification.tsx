import React, { useState, useEffect } from 'react';
import { Device, VerificationReport, LevelResult, SanitizationCertificate } from '../types';
import { fetchDevices, runVerification, issueCertificate } from '../services/api';
import { ShieldCheck, ShieldX, ShieldAlert, AlertCircle, FileCheck2, Award, ChevronDown, ChevronUp } from 'lucide-react';

const LEVEL_LABELS: Record<string, string> = {
  L1Logical: 'L1 · Logical Filesystem',
  L2HostVisible: 'L2 · Host-Visible Block',
  L3DeviceReported: 'L3 · Device-Reported (NVMe)',
  L4Forensic: 'L4 · Forensic Recovery',
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
    PASS: { cls: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30', label: 'PASS' },
    PASSED: { cls: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30', label: 'PASS' },
    UNSUPPORTED: { cls: 'bg-gray-600/30 text-gray-400 border-gray-600/30', label: 'UNSUPPORTED' },
    NOT_AVAILABLE: { cls: 'bg-amber-500/20 text-amber-300 border-amber-500/30', label: 'NOT AVAILABLE' },
    INCONCLUSIVE: { cls: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30', label: 'INCONCLUSIVE' },
    FAIL: { cls: 'bg-red-500/20 text-red-300 border-red-500/30', label: 'FAIL' },
    FAILED: { cls: 'bg-red-500/20 text-red-300 border-red-500/30', label: 'FAIL' },
    ERROR: { cls: 'bg-red-500/20 text-red-300 border-red-500/30', label: 'ERROR' },
  }[norm] ?? { cls: 'bg-gray-600/30 text-gray-400 border-gray-600/30', label: status };

  return (
    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold font-mono border ${cfg.cls}`}>
      {cfg.label}
    </span>
  );
}

function LevelCard({ result }: { result: LevelResult }) {
  const [expanded, setExpanded] = useState(false);
  const norm = result.status.toUpperCase();

  const borderColor = {
    PASS: 'border-emerald-500/30',
    PASSED: 'border-emerald-500/30',
    UNSUPPORTED: 'border-gray-700/50',
    NOT_AVAILABLE: 'border-amber-500/40',
    INCONCLUSIVE: 'border-yellow-500/40',
    FAIL: 'border-red-500/40',
    FAILED: 'border-red-500/40',
    ERROR: 'border-red-500/40',
  }[norm] ?? 'border-gray-700/50';

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
    PASS: 'text-emerald-400',
    PASSED: 'text-emerald-400',
    UNSUPPORTED: 'text-gray-500',
    NOT_AVAILABLE: 'text-amber-400',
    INCONCLUSIVE: 'text-yellow-400',
    FAIL: 'text-red-400',
    FAILED: 'text-red-400',
    ERROR: 'text-amber-400',
  }[norm] ?? 'text-gray-500';

  return (
    <div className={`rounded-xl border ${borderColor} bg-surface overflow-hidden`}>
      <button
        onClick={() => setExpanded((e) => !e)}
        className="w-full p-4 flex items-center justify-between text-left hover:bg-surface-highlight/20 transition-colors"
      >
        <div className="flex items-center space-x-3">
          <Icon className={`w-5 h-5 flex-shrink-0 ${iconColor}`} />
          <div>
            <div className="text-sm font-semibold text-gray-200">
              {LEVEL_LABELS[result.level] ?? result.level}
            </div>
            <div className="text-xs text-gray-500 mt-0.5 font-mono">
              Weight {LEVEL_WEIGHTS[result.level] ?? '?'} · Confidence {result.confidence_pct}%
            </div>
          </div>
        </div>
        <div className="flex items-center space-x-3">
          <StatusBadge status={result.status} />
          {expanded ? (
            <ChevronUp className="w-4 h-4 text-gray-500" />
          ) : (
            <ChevronDown className="w-4 h-4 text-gray-500" />
          )}
        </div>
      </button>
      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-gray-800/60">
          {result.method && (
            <div className="text-[11px] font-mono text-blue-400 mt-3">
              <span className="text-gray-500">Method: </span>{result.method}
            </div>
          )}
          <p className="text-xs text-gray-300 leading-relaxed">{result.detail}</p>
          <div className="space-y-1">
            {result.evidence?.map((e, i) => (
              <div key={i} className="text-[11px] font-mono text-gray-400 flex items-start space-x-2">
                <span className="text-gray-600 select-none">›</span>
                <span>{e}</span>
              </div>
            ))}
          </div>
          {result.limitations && result.limitations.length > 0 && (
            <div className="pt-2 border-t border-gray-800/40">
              <div className="text-[10px] font-semibold text-amber-400 uppercase tracking-wider mb-1">Declared Limitations:</div>
              {result.limitations.map((lim, idx) => (
                <div key={idx} className="text-[10px] text-gray-400 italic flex items-start space-x-1.5">
                  <span className="text-amber-500">•</span>
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
  const color = pct >= 80 ? '#10b981' : pct >= 60 ? '#f59e0b' : '#ef4444';

  return (
    <svg width="96" height="96" viewBox="0 0 96 96" className="rotate-[-90deg]">
      <circle cx="48" cy="48" r={r} fill="none" stroke="#1f2937" strokeWidth="8" />
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
        className="rotate-[90deg]"
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
      const r = await runVerification(selectedDevice, method, true);
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
        true,
        'SinglePassZero'
      );
      setCert(c);
    } finally {
      setIsIssuingCert(false);
    }
  };

  return (
    <div className="p-8 space-y-6">
      <div>
        <h3 className="text-xl font-bold text-white">Multi-Level Verification</h3>
        <p className="text-xs text-gray-400">L1–L4 forensic confidence matrix with Ed25519 attestation</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Config panel */}
        <div className="space-y-4">
          <div className="p-5 rounded-xl bg-surface border border-gray-800 space-y-4">
            <h4 className="text-sm font-semibold text-white">Target Device</h4>
            <div className="space-y-2">
              {devices.filter((d) => !d.system_disk && !d.boot_device).map((d) => (
                <button
                  key={d.stable_id}
                  onClick={() => setSelectedDevice(d)}
                  className={`w-full text-left p-3 rounded-lg border text-xs transition-all ${
                    selectedDevice?.stable_id === d.stable_id
                      ? 'border-blue-500 bg-blue-600/10'
                      : 'border-gray-800 hover:border-gray-700 bg-surface-highlight/40'
                  }`}
                >
                  <div className="font-semibold text-gray-200">{d.model}</div>
                  <div className="font-mono text-gray-400 mt-0.5">{d.path} · {typeof d.media_type === 'string' ? d.media_type : 'Unknown'}</div>
                </button>
              ))}
            </div>
          </div>

          <div className="p-5 rounded-xl bg-surface border border-gray-800 space-y-3">
            <h4 className="text-sm font-semibold text-white">Sanitization Method</h4>
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value)}
              className="w-full bg-surface-highlight border border-gray-700 rounded-lg px-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-blue-500"
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
              className="w-full py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-gray-800 disabled:text-gray-500 text-white text-sm font-semibold transition-colors"
            >
              {isRunning ? 'Running L1–L4 Scan...' : 'Run Verification Matrix'}
            </button>
          </div>
        </div>

        {/* Results panel */}
        <div className="lg:col-span-2 space-y-4">
          {!report && !isRunning && (
            <div className="flex flex-col items-center justify-center h-64 rounded-xl border border-dashed border-gray-700 text-gray-500">
              <ShieldCheck className="w-12 h-12 mb-3 opacity-30" />
              <p className="text-sm">Select a device and run verification to see L1–L4 results</p>
            </div>
          )}

          {isRunning && (
            <div className="flex flex-col items-center justify-center h-64 rounded-xl border border-gray-800 bg-surface space-y-4">
              <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
              <p className="text-sm text-gray-400">Executing L1 → L2 → L3 → L4 verification levels...</p>
            </div>
          )}

          {report && (
            <>
              {/* Summary header */}
              <div className="p-5 rounded-xl bg-surface border border-gray-800 flex items-center justify-between">
                <div>
                  <div className={`text-lg font-bold ${report.overall_passed ? 'text-emerald-400' : 'text-red-400'}`}>
                    {report.overall_passed ? '✓ Verification Passed' : '✗ Verification Failed'}
                  </div>
                  <div className="text-xs text-gray-400 mt-1">
                    Target: <span className="font-mono text-gray-300">{report.target_id}</span>
                    {report.unsupported_levels.length > 0 && (
                      <span className="ml-2 text-gray-500">
                        · {report.unsupported_levels.length} level(s) not applicable
                      </span>
                    )}
                  </div>
                  <div className="text-[10px] text-gray-500 mt-1 font-mono">{report.timestamp_utc}</div>
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
              <div className="p-5 rounded-xl bg-surface border border-gray-800 space-y-4">
                <div className="flex items-center space-x-2">
                  <Award className="w-5 h-5 text-yellow-400" />
                  <h4 className="text-sm font-semibold text-white">Issue Attestation Certificate</h4>
                </div>
                <p className="text-xs text-gray-400">
                  Generates an Ed25519-signed <code className="text-blue-300">SanitizationCertificate</code> binding
                  this verification result to the session signing key. A judge can verify authorship using the
                  public key displayed below.
                </p>
                {!cert ? (
                  <button
                    disabled={isIssuingCert}
                    onClick={handleIssueCertificate}
                    className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-yellow-600/80 hover:bg-yellow-500/80 text-white text-sm font-semibold transition-colors"
                  >
                    <FileCheck2 className="w-4 h-4" />
                    <span>{isIssuingCert ? 'Issuing...' : 'Issue Certificate'}</span>
                  </button>
                ) : (
                  <div className="space-y-3 text-xs font-mono">
                    <div className="p-3 rounded-lg bg-yellow-950/30 border border-yellow-600/20 space-y-2">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Cert ID</span>
                        <span className="text-yellow-300">{cert.cert_id}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Version</span>
                        <span className="text-gray-200">{cert.cert_version}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Issued At</span>
                        <span className="text-gray-200">{cert.issued_at}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Key Scope</span>
                        <span className="text-blue-300">{cert.signing_identity.scope.toUpperCase()}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Key ID</span>
                        <span className="text-gray-200 break-all">{cert.signing_identity.key_id.substring(0, 24)}…</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Public Key</span>
                        <span className="text-gray-200 break-all">{cert.signing_identity.public_key_hex.substring(0, 24)}…</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Signature</span>
                        <span className="text-emerald-300">{cert.signature.substring(0, 24)}…</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Audit Events</span>
                        <span className="text-gray-200">{cert.audit_event_count}</span>
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-blue-950/30 border border-blue-600/20 text-blue-200/80 leading-relaxed">
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
