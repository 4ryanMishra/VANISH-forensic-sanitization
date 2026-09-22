import React, { useState, useEffect } from 'react';
import { AuditEvent } from '../types';
import { fetchAuditLog } from '../services/api';
import { FileDown, Link, CheckCircle2, Hash, Clock, Shield } from 'lucide-react';

function formatActor(actor: AuditEvent['actor']): string {
  if (actor === 'SystemEngine') return 'System Engine';
  if (actor === 'AutomatedPolicy') return 'Automated Policy';
  if (typeof actor === 'object' && 'User' in actor) return `User: ${actor.User}`;
  return String(actor);
}

function hashShort(h: string): string {
  if (!h) return 'GENESIS';
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
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-[10px] font-mono font-bold tracking-widest text-telemetry uppercase bg-telemetry/10 px-2 py-0.5 rounded border border-telemetry/20">
              IMMUTABLE AUDIT TRAIL
            </span>
            <span className="text-[10px] font-mono text-charcoal/50">SHA-256 HASH CHAIN</span>
          </div>
          <h2 className="text-xl font-bold text-charcoal tracking-tight mt-1">Tamper-Evident Forensic Audit Ledger</h2>
          <p className="text-xs text-charcoal/60 mt-0.5">
            Strict cryptographically chained sequence of all discovery, carving, sanitization, and verification actions
          </p>
        </div>
        <div className="flex items-center space-x-3">
          {integrityOk !== null && (
            <div className={`flex items-center space-x-1.5 text-xs font-mono font-bold px-3 py-1.5 rounded-lg border ${
              integrityOk ? 'bg-verified/10 text-verified border-verified/30' : 'bg-vermilion/10 text-vermilion border-vermilion/30'
            }`}>
              <Shield className="w-3.5 h-3.5" />
              <span>{integrityOk ? 'Chain Integrity: VALID' : 'Chain Integrity: BROKEN'}</span>
            </div>
          )}
          <button
            onClick={exportJson}
            className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border border-border bg-white text-xs font-semibold text-charcoal hover:bg-surface-elevated shadow-subtle transition-colors"
          >
            <FileDown className="w-3.5 h-3.5 text-telemetry" />
            <span>Export JSON Log</span>
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-48 text-charcoal/50 bg-white border border-border rounded-xl shadow-subtle text-xs font-mono">
          <div className="w-5 h-5 border-2 border-telemetry border-t-transparent rounded-full animate-spin mr-3" />
          Loading audit events…
        </div>
      ) : events.length === 0 ? (
        <div className="flex items-center justify-center h-48 text-charcoal/40 text-xs font-mono bg-white border border-dashed border-border rounded-xl shadow-subtle">
          No audit events recorded yet. Run a sanitization or carving operation to initialize the chain.
        </div>
      ) : (
        <div className="space-y-3">
          {events.map((evt, idx) => (
            <div
              key={evt.event_id}
              className="p-5 rounded-xl bg-white border border-border space-y-3 shadow-subtle"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-6 h-6 rounded-full bg-surface-elevated border border-border flex items-center justify-center text-[10px] font-mono font-bold text-charcoal">
                    {evt.sequence_number}
                  </div>
                  <div>
                    <div className="text-sm font-bold text-charcoal">{evt.operation}</div>
                    <div className="text-xs text-charcoal/50 font-mono">{formatActor(evt.actor)}</div>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                    evt.result_status === 'SUCCESS'
                      ? 'bg-verified/10 text-verified border border-verified/30'
                      : 'bg-vermilion/10 text-vermilion border border-vermilion/30'
                  }`}>
                    {evt.result_status}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono text-charcoal/60 pt-1 border-t border-border">
                <div className="flex items-center space-x-2">
                  <Clock className="w-3.5 h-3.5 text-charcoal/40" />
                  <span>{typeof evt.timestamp === 'string' ? evt.timestamp : new Date(evt.timestamp).toISOString()}</span>
                </div>
                <div className="flex items-center space-x-2">
                  <Hash className="w-3.5 h-3.5 text-charcoal/40" />
                  <span>Target ID: <strong className="text-charcoal">{evt.target_id}</strong></span>
                </div>
              </div>

              {/* Hash chain visualization */}
              <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono pt-1">
                <div className="px-2 py-0.5 rounded bg-surface-elevated text-charcoal/60 border border-border">
                  prev: {hashShort(evt.previous_event_hash)}
                </div>
                <Link className="w-3 h-3 text-charcoal/40" />
                <div className="px-2 py-0.5 rounded bg-verified/10 text-verified font-bold border border-verified/30">
                  current: {hashShort(evt.current_event_hash)}
                </div>
                {idx < events.length - 1 && (
                  <CheckCircle2 className="w-3.5 h-3.5 text-verified" />
                )}
              </div>

              {evt.verification_summary && (
                <div className="text-xs text-charcoal/70 font-sans italic bg-surface-elevated p-2 rounded border border-border">
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
