import React, { useState, useEffect } from 'react';
import { AuditEvent, SanitizationCertificate } from '../types';
import { fetchAuditLog } from '../services/api';
import { FileDown, Link, CheckCircle2, Hash, Clock, Shield } from 'lucide-react';

function formatActor(actor: AuditEvent['actor']): string {
  if (actor === 'SystemEngine') return 'System Engine';
  if (actor === 'AutomatedPolicy') return 'Automated Policy';
  if (typeof actor === 'object' && 'User' in actor) return `User: ${actor.User}`;
  return String(actor);
}

function hashShort(h: string): string {
  return `${h.substring(0, 8)}…${h.substring(h.length - 6)}`;
}

export const AuditTrail: React.FC = () => {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [integrityOk, setIntegrityOk] = useState<boolean | null>(null);

  useEffect(() => {
    fetchAuditLog().then((evts) => {
      setEvents(evts);
      setLoading(false);
      // Verify hash chain integrity client-side
      if (evts.length > 0) {
        let ok = true;
        for (let i = 1; i < evts.length; i++) {
          if (evts[i].previous_event_hash !== evts[i - 1].current_event_hash) {
            ok = false;
            break;
          }
        }
        setIntegrityOk(ok);
      } else {
        setIntegrityOk(true);
      }
    });
  }, []);

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(events, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vanish-audit-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xl font-bold text-white">Audit Trail</h3>
          <p className="text-xs text-gray-400">SHA-256 hash-chained tamper-evident event log</p>
        </div>
        <div className="flex items-center space-x-3">
          {integrityOk !== null && (
            <div className={`flex items-center space-x-1.5 text-xs font-semibold ${integrityOk ? 'text-emerald-400' : 'text-red-400'}`}>
              <Shield className="w-4 h-4" />
              <span>{integrityOk ? 'Chain Integrity: VALID' : 'Chain Integrity: BROKEN'}</span>
            </div>
          )}
          <button
            onClick={exportJson}
            className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border border-gray-700 text-xs text-gray-300 hover:border-gray-500 hover:text-white transition-colors"
          >
            <FileDown className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-48 text-gray-500">
          <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mr-3" />
          Loading audit events…
        </div>
      ) : events.length === 0 ? (
        <div className="flex items-center justify-center h-48 text-gray-500 text-sm">
          No audit events recorded yet. Run a sanitization to start the chain.
        </div>
      ) : (
        <div className="space-y-2">
          {events.map((evt, idx) => (
            <div
              key={evt.event_id}
              className="p-4 rounded-xl bg-surface border border-gray-800 space-y-2"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-6 h-6 rounded-full bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-[10px] font-bold text-blue-400">
                    {evt.sequence_number}
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-gray-200">{evt.operation}</div>
                    <div className="text-xs text-gray-500">{formatActor(evt.actor)}</div>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                    evt.result_status === 'SUCCESS'
                      ? 'bg-emerald-500/15 text-emerald-400'
                      : 'bg-red-500/15 text-red-400'
                  }`}>
                    {evt.result_status}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono">
                <div className="flex items-center space-x-2 text-gray-500">
                  <Clock className="w-3 h-3" />
                  <span className="text-gray-400">{typeof evt.timestamp === 'string' ? evt.timestamp : new Date(evt.timestamp).toISOString()}</span>
                </div>
                <div className="flex items-center space-x-2 text-gray-500">
                  <Hash className="w-3 h-3" />
                  <span className="text-gray-400">Target: {evt.target_id}</span>
                </div>
              </div>

              {/* Hash chain visualization */}
              <div className="flex items-center space-x-2 text-[10px] font-mono">
                <div className="px-2 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700">
                  prev: {hashShort(evt.previous_event_hash)}
                </div>
                <Link className="w-3 h-3 text-gray-600" />
                <div className="px-2 py-0.5 rounded bg-gray-800 text-emerald-400 border border-emerald-900/40">
                  hash: {hashShort(evt.current_event_hash)}
                </div>
                {idx < events.length - 1 && (
                  <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                )}
              </div>

              {evt.verification_summary && (
                <div className="text-[11px] text-gray-400 italic">
                  ↳ {evt.verification_summary}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ── Separate Reports page with certificate display ────────────────────────────

interface ReportsProps {
  latestCert?: SanitizationCertificate;
}

export const Reports: React.FC<ReportsProps> = ({ latestCert }) => {
  const exportCert = (cert: SanitizationCertificate) => {
    const blob = new Blob([JSON.stringify(cert, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vanish-cert-${cert.cert_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-8 space-y-6">
      <div>
        <h3 className="text-xl font-bold text-white">Certification Reports</h3>
        <p className="text-xs text-gray-400">Ed25519-signed SanitizationCertificates — run Verification to generate</p>
      </div>

      {!latestCert ? (
        <div className="flex flex-col items-center justify-center h-64 rounded-xl border border-dashed border-gray-700 text-gray-500 space-y-2">
          <FileDown className="w-10 h-10 opacity-30" />
          <p className="text-sm">No certificate issued yet</p>
          <p className="text-xs text-gray-600">Complete a Verification run and issue a certificate</p>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="p-6 rounded-xl bg-surface border border-yellow-700/30 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs text-yellow-400 font-mono font-semibold">{latestCert.cert_id}</div>
                <h4 className="text-lg font-bold text-white mt-1">Sanitization Certificate v{latestCert.cert_version}</h4>
              </div>
              <button
                onClick={() => exportCert(latestCert)}
                className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-yellow-700/50 hover:bg-yellow-600/60 text-yellow-200 text-sm font-semibold transition-colors"
              >
                <FileDown className="w-4 h-4" />
                <span>Export JSON</span>
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div className="space-y-3">
                <div className="p-3 rounded-lg bg-surface-highlight/50 border border-gray-800">
                  <div className="text-gray-400 mb-2 font-semibold">Device Identity</div>
                  <div className="font-mono space-y-1 text-gray-300">
                    <div>{latestCert.device_identity.model}</div>
                    <div className="text-gray-400">S/N: {latestCert.device_identity.serial}</div>
                    <div className="text-gray-400">{(latestCert.device_identity.capacity_bytes / 1e9).toFixed(1)} GB · {latestCert.device_identity.media_type}</div>
                  </div>
                </div>
                <div className="p-3 rounded-lg bg-surface-highlight/50 border border-gray-800">
                  <div className="text-gray-400 mb-2 font-semibold">Operation</div>
                  <div className="font-mono space-y-1 text-gray-300">
                    <div>{latestCert.operation_summary.method}</div>
                    <div className="text-gray-400">Standard: {latestCert.operation_summary.standard}</div>
                    <div className="text-gray-400">Passes: {latestCert.operation_summary.passes_completed}</div>
                    {latestCert.operation_summary.simulation_mode && (
                      <div className="text-amber-400">[simulation_mode=true]</div>
                    )}
                  </div>
                </div>
              </div>
              <div className="space-y-3">
                <div className="p-3 rounded-lg bg-surface-highlight/50 border border-gray-800">
                  <div className="text-gray-400 mb-2 font-semibold">Verification Result</div>
                  <div className="space-y-1">
                    <div className={`text-sm font-bold ${latestCert.verification_result.overall_passed ? 'text-emerald-400' : 'text-red-400'}`}>
                      {latestCert.verification_result.overall_passed ? '✓ PASSED' : '✗ FAILED'}
                    </div>
                    <div className="text-gray-400 font-mono">Confidence: {latestCert.verification_result.confidence_pct}%</div>
                    <div className="text-gray-400 font-mono">Events in chain: {latestCert.audit_event_count}</div>
                  </div>
                </div>
                <div className="p-3 rounded-lg bg-surface-highlight/50 border border-gray-800">
                  <div className="text-gray-400 mb-2 font-semibold">Signing Identity</div>
                  <div className="font-mono space-y-1 text-gray-300 break-all">
                    <div className="text-[10px]">Key ID: {latestCert.signing_identity.key_id.substring(0, 20)}…</div>
                    <div className="text-[10px]">Pub: {latestCert.signing_identity.public_key_hex.substring(0, 20)}…</div>
                    <div className="text-[10px] text-emerald-400">Sig: {latestCert.signature.substring(0, 20)}…</div>
                    <div className="text-blue-300 text-[10px]">{latestCert.signing_identity.scope.toUpperCase()}</div>
                  </div>
                </div>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-blue-950/30 border border-blue-700/20 text-xs text-blue-200/80">
              {latestCert.trust_scope_note}
            </div>

            <div className="p-3 rounded-lg bg-gray-800/50 border border-gray-700/50">
              <div className="text-xs text-gray-400 mb-1">Audit Chain Root Hash</div>
              <div className="font-mono text-[11px] text-gray-300 break-all">{latestCert.audit_chain_root_hash}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
