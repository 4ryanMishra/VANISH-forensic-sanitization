import React from 'react';
import { VerificationResult } from '../types';

export const Verification: React.FC = () => {
  const result: VerificationResult = {
    verification_id: 'ver-88219-01',
    target_id: 'disk-sandisk-16g',
    l1_logical: {
      status: 'Verified',
      description: 'Filesystem metadata, partitions, and MBR/GPT tables cleared.',
      sectors_checked: 2048,
      matching_expected_pattern_pct: 100.0,
      mean_entropy: 0.0,
    },
    l2_host_visible: {
      status: 'Verified',
      description: 'Full-range sequential sampling verified zero pattern (0x00) across 100% of sample blocks.',
      sectors_checked: 32768,
      matching_expected_pattern_pct: 100.0,
      mean_entropy: 0.001,
    },
    l3_device_reported: {
      status: 'Unsupported',
      description: 'USB Mass Storage controller does not support device-reported internal sanitize status logs.',
    },
    l4_forensic_validation: {
      status: 'Verified',
      description: 'VANISH forensic carving & signature reconstruction pipeline executed with zero recoverable artifacts.',
    },
    scope_description: 'Full user-addressable LBA range (LBA 0 through LBA 31,249,999).',
    warnings: [
      'Removable USB flash controller wear-leveling spare area cannot be interrogated via standard host command set.',
    ],
    summary_statement: 'No target artifact was recovered by the specified VANISH validation procedure.',
  };

  return (
    <div className="p-8 space-y-6">
      <div>
        <h3 className="text-xl font-bold text-white">L1–L4 Multi-Level Verification</h3>
        <p className="text-xs text-gray-400">Post-sanitization verification matrix and forensic assurance report</p>
      </div>

      <div className="space-y-6">
        {/* Main Statement Banner */}
        <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-2">
          <div className="text-xs font-mono text-emerald-400 font-semibold uppercase">Official Attestation Finding</div>
          <p className="text-base text-gray-200 font-semibold italic">"{result.summary_statement}"</p>
          <div className="text-xs text-gray-400 pt-2 border-t border-gray-800">
            Scope: <span className="text-gray-300 font-mono">{result.scope_description}</span>
          </div>
        </div>

        {/* 4 Levels Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* L1 */}
          <div className="p-5 rounded-xl bg-surface border border-gray-800 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="w-6 h-6 rounded-full bg-blue-500/10 text-blue-400 text-xs font-bold flex items-center justify-center">1</span>
                <h4 className="font-bold text-white text-sm">L1 — Logical Metadata</h4>
              </div>
              <span className="px-2 py-0.5 rounded text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                {result.l1_logical.status}
              </span>
            </div>
            <p className="text-xs text-gray-400">{result.l1_logical.description}</p>
          </div>

          {/* L2 */}
          <div className="p-5 rounded-xl bg-surface border border-gray-800 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="w-6 h-6 rounded-full bg-blue-500/10 text-blue-400 text-xs font-bold flex items-center justify-center">2</span>
                <h4 className="font-bold text-white text-sm">L2 — Host-Visible Sectors</h4>
              </div>
              <span className="px-2 py-0.5 rounded text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                {result.l2_host_visible.status}
              </span>
            </div>
            <p className="text-xs text-gray-400">{result.l2_host_visible.description}</p>
            <div className="text-[11px] text-gray-500 font-mono">
              Entropy: {result.l2_host_visible.mean_entropy} • Pattern Match: {result.l2_host_visible.matching_expected_pattern_pct}%
            </div>
          </div>

          {/* L3 */}
          <div className="p-5 rounded-xl bg-surface border border-gray-800 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="w-6 h-6 rounded-full bg-blue-500/10 text-blue-400 text-xs font-bold flex items-center justify-center">3</span>
                <h4 className="font-bold text-white text-sm">L3 — Device-Reported</h4>
              </div>
              <span className="px-2 py-0.5 rounded text-xs font-medium bg-gray-500/10 text-gray-400 border border-gray-500/20">
                {result.l3_device_reported.status}
              </span>
            </div>
            <p className="text-xs text-gray-400">{result.l3_device_reported.description}</p>
          </div>

          {/* L4 */}
          <div className="p-5 rounded-xl bg-surface border border-gray-800 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="w-6 h-6 rounded-full bg-purple-500/10 text-purple-400 text-xs font-bold flex items-center justify-center">4</span>
                <h4 className="font-bold text-white text-sm">L4 — Forensic Validation</h4>
              </div>
              <span className="px-2 py-0.5 rounded text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                {result.l4_forensic_validation.status}
              </span>
            </div>
            <p className="text-xs text-gray-400">{result.l4_forensic_validation.description}</p>
          </div>
        </div>
      </div>
    </div>
  );
};
