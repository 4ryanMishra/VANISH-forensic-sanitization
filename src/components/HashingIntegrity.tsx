import { useEffect, useState } from 'react';
import { HashStatusReport, HashResult } from '../types';
import { fetchHashStatus } from '../services/api';

export function HashingIntegrity() {
  const [status, setStatus] = useState<HashStatusReport | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    fetchHashStatus().then(res => {
      if (mounted) {
        setStatus(res);
        setLoading(false);
      }
    });
    return () => { mounted = false; };
  }, []);

  if (loading) {
    return <div className="text-gray-400 text-sm animate-pulse">Loading hashing integrity data...</div>;
  }

  if (!status) return null;

  const sha256Results = status.results.filter(r => r.algorithm === 'SHA-256');
  const blake3Results = status.results.filter(r => r.algorithm === 'BLAKE3');

  return (
    <div className="bg-slate-900 border border-slate-700 rounded-lg p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
            <svg className="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            Cryptographic Integrity Architecture
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            VANISH utilizes dual hashing algorithms for distinct, strictly separated purposes.
          </p>
        </div>
        {!status.backend_available && (
          <div className="bg-amber-900/50 text-amber-300 border border-amber-700/50 px-3 py-1 rounded text-xs font-medium uppercase tracking-wider">
            Simulation Mode
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* SHA-256 Evidence Column */}
        <div className="bg-slate-800 rounded border border-slate-600 p-4">
          <div className="flex items-center justify-between mb-4 border-b border-slate-700 pb-2">
            <div>
              <h3 className="text-emerald-400 font-medium text-lg flex items-center gap-2">
                SHA-256
                <span className="bg-emerald-900/50 text-emerald-300 text-[10px] px-2 py-0.5 rounded uppercase font-bold tracking-widest">
                  Evidence
                </span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">Canonical hash for artifact identity and report verification.</p>
            </div>
          </div>
          
          <div className="space-y-4">
            {sha256Results.length === 0 ? (
              <div className="text-slate-500 text-sm italic">No recent SHA-256 computations</div>
            ) : (
              sha256Results.map((res, i) => <HashResultRow key={i} result={res} />)
            )}
          </div>
        </div>

        {/* BLAKE3 Speed Column */}
        <div className="bg-slate-800 rounded border border-slate-600 p-4">
          <div className="flex items-center justify-between mb-4 border-b border-slate-700 pb-2">
            <div>
              <h3 className="text-cyan-400 font-medium text-lg flex items-center gap-2">
                BLAKE3
                <span className="bg-cyan-900/50 text-cyan-300 text-[10px] px-2 py-0.5 rounded uppercase font-bold tracking-widest">
                  Processing
                </span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">High-throughput internal hash for storage scans and dedup.</p>
            </div>
          </div>

          <div className="space-y-4">
            {blake3Results.length === 0 ? (
              <div className="text-slate-500 text-sm italic">No recent BLAKE3 computations</div>
            ) : (
              blake3Results.map((res, i) => <HashResultRow key={i} result={res} />)
            )}
          </div>
        </div>
      </div>
      
      <div className="text-xs text-slate-500 bg-slate-900/50 p-3 rounded border border-slate-700/50 flex items-start gap-2">
        <svg className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <p>
          <strong className="text-slate-300">Important:</strong> BLAKE3 is utilized exclusively for performance-critical internal operations. It does not replace SHA-256 and is not presented as a "more secure" alternative. SHA-256 remains the sole canonical standard for all forensic evidence verification.
        </p>
      </div>
    </div>
  );
}

function HashResultRow({ result }: { result: HashResult }) {
  return (
    <div className="bg-slate-900/80 rounded p-3 border border-slate-700">
      <div className="flex justify-between items-start mb-1.5">
        <span className="text-xs font-medium text-slate-300">{result.source_label}</span>
        <span className="text-[10px] text-slate-500">{new Date(result.computed_at).toLocaleTimeString()}</span>
      </div>
      <div className="font-mono text-xs break-all text-slate-400 bg-black/40 p-2 rounded">
        {result.simulation_mode ? (
          <span className="text-amber-500/70 line-through mr-2" title="Simulated value">
            [SIMULATED]
          </span>
        ) : null}
        {result.digest}
      </div>
    </div>
  );
}
