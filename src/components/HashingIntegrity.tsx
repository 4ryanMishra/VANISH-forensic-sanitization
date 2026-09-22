import React, { useEffect, useState } from 'react';
import { HashStatusReport, HashResult } from '../types';
import { fetchHashStatus } from '../services/api';
import { ShieldCheck, Zap, Info } from 'lucide-react';

export const HashingIntegrity: React.FC = () => {
  const [status, setStatus] = useState<HashStatusReport | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    fetchHashStatus().then((res) => {
      if (mounted) {
        setStatus(res);
        setLoading(false);
      }
    });
    return () => {
      mounted = false;
    };
  }, []);

  if (loading) {
    return (
      <div className="p-4 rounded-lg bg-surface border border-border text-charcoal-muted text-xs font-mono animate-pulse">
        Polling native cryptographic hashing telemetry...
      </div>
    );
  }

  if (!status) return null;

  const sha256Results = status.results.filter((r) => r.algorithm === 'SHA-256');
  const blake3Results = status.results.filter((r) => r.algorithm === 'BLAKE3');

  return (
    <div className="bg-surface border border-border rounded-lg p-6 space-y-6 font-sans">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border pb-4">
        <div>
          <div className="inline-flex items-center space-x-1.5 text-xs font-mono uppercase tracking-wider text-charcoal-muted mb-1">
            <span>Cryptographic Hashing Architecture</span>
          </div>
          <h3 className="text-base font-semibold text-charcoal">
            Strict Separation: Canonical Evidence vs. High-Throughput Processing
          </h3>
        </div>
        {!status.backend_available && (
          <span className="px-2.5 py-1 rounded bg-amber-surface text-amber-dark border border-amber-border text-xs font-mono font-semibold">
            Simulation Fallback
          </span>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* SHA-256 Canonical Evidence */}
        <div className="p-4 rounded-lg bg-verified-surface/30 border border-verified-border space-y-3">
          <div className="flex items-center justify-between border-b border-verified-border/60 pb-2">
            <div className="flex items-center space-x-2 text-verified-dark font-semibold text-sm">
              <ShieldCheck className="w-4 h-4 text-verified" />
              <span>SHA-256 (Canonical Evidence)</span>
            </div>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-verified-surface text-verified-dark font-bold border border-verified-border">
              Standard
            </span>
          </div>
          <p className="text-xs text-charcoal-secondary leading-relaxed">
            Sole standard for digital forensics artifact identification, disk image checksums, tamper-evident audit chains, and court-admissible certificate attestation.
          </p>

          <div className="space-y-2">
            {sha256Results.length === 0 ? (
              <div className="text-xs text-charcoal-muted font-mono italic">No active SHA-256 digests</div>
            ) : (
              sha256Results.map((res, i) => <HashResultCard key={i} result={res} />)
            )}
          </div>
        </div>

        {/* BLAKE3 High Throughput */}
        <div className="p-4 rounded-lg bg-telemetry-surface/30 border border-telemetry-border space-y-3">
          <div className="flex items-center justify-between border-b border-telemetry-border/60 pb-2">
            <div className="flex items-center space-x-2 text-telemetry-dark font-semibold text-sm">
              <Zap className="w-4 h-4 text-telemetry" />
              <span>BLAKE3 (Internal Processing)</span>
            </div>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-telemetry-surface text-telemetry-dark font-bold border border-telemetry-border">
              Performance
            </span>
          </div>
          <p className="text-xs text-charcoal-secondary leading-relaxed">
            Optimized tree-hashing algorithm utilized strictly for multi-gigabyte memory scans, cluster deduplication, cache keys, and internal state machine speed.
          </p>

          <div className="space-y-2">
            {blake3Results.length === 0 ? (
              <div className="text-xs text-charcoal-muted font-mono italic">No active BLAKE3 digests</div>
            ) : (
              blake3Results.map((res, i) => <HashResultCard key={i} result={res} />)
            )}
          </div>
        </div>
      </div>

      <div className="flex items-start space-x-2 text-[11px] text-charcoal-muted bg-surface-subtle p-3 rounded border border-border">
        <Info className="w-4 h-4 text-charcoal-muted shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <strong className="text-charcoal-secondary font-semibold">Integrity Rule:</strong> BLAKE3 does not replace SHA-256 and is not presented as a "more secure" alternative. SHA-256 remains the sole canonical standard for all forensic evidence verification.
        </p>
      </div>
    </div>
  );
};

const HashResultCard: React.FC<{ result: HashResult }> = ({ result }) => {
  return (
    <div className="p-3 bg-surface rounded border border-border space-y-1.5 font-mono text-xs">
      <div className="flex justify-between items-start text-[11px]">
        <span className="font-semibold text-charcoal">{result.source_label}</span>
        <span className="text-charcoal-muted">{new Date(result.computed_at).toLocaleTimeString()}</span>
      </div>
      <div className="text-[11px] text-charcoal-secondary bg-surface-subtle p-2 rounded border border-border-subtle break-all font-mono">
        {result.simulation_mode && (
          <span className="text-amber font-semibold mr-1.5">[SIMULATION]</span>
        )}
        {result.digest}
      </div>
    </div>
  );
};
