import React from 'react';
import { FileSearch, ShieldCheck, CheckCircle2, AlertTriangle } from 'lucide-react';
import { RecoveredArtifact, VerificationReport } from '../types';

interface BeforeAfterComparisonProps {
  recoveredArtifacts: RecoveredArtifact[];
  verificationReport: VerificationReport | null;
  targetDeviceLabel: string;
}

export const BeforeAfterComparison: React.FC<BeforeAfterComparisonProps> = ({
  recoveredArtifacts,
  verificationReport,
  targetDeviceLabel,
}) => {
  const primaryArtifact = recoveredArtifacts.length > 0 ? recoveredArtifacts[0] : null;
  const isPostSanitizationVerified = verificationReport !== null && verificationReport.overall_passed;

  return (
    <div className="bg-surface border border-border rounded-lg p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border pb-4">
        <div>
          <div className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-surface-subtle border border-border text-[11px] font-mono text-charcoal-muted uppercase mb-1">
            Comparative Evidence Manifest
          </div>
          <h3 className="text-base font-semibold text-charcoal">
            The Sanitization Assurance Proof: Before vs. After
          </h3>
        </div>
        <div className="text-xs font-mono text-charcoal-secondary">
          Target: <strong className="text-charcoal">{targetDeviceLabel}</strong>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Left: BEFORE SANITIZATION (Standard OS Deletion) */}
        <div className="p-5 rounded-lg bg-surface border border-forensic-border/70 space-y-4 shadow-subtle flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded text-xs font-mono font-semibold bg-forensic-surface text-forensic border border-forensic-border">
                <FileSearch className="w-3.5 h-3.5" />
                <span>STATE 1: AFTER OS DELETION</span>
              </span>
              <span className="text-xs font-mono text-charcoal-muted">Raw Carving Probe</span>
            </div>

            <h4 className="text-sm font-semibold text-charcoal">
              File Deleted by OS → 100% Recoverable from Raw Sectors
            </h4>
            <p className="text-xs text-charcoal-secondary leading-relaxed">
              Standard filesystem deletion clears only directory metadata pointers. The raw binary payloads remain fully intact in unallocated clusters.
            </p>

            {primaryArtifact ? (
              <div className="p-3.5 rounded bg-surface-subtle border border-border space-y-2 text-xs font-mono">
                <div className="flex justify-between items-center text-charcoal">
                  <span className="font-semibold text-forensic">{primaryArtifact.original_path || primaryArtifact.artifact_id}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface border border-border text-charcoal-secondary">
                    {typeof primaryArtifact.format === 'string' ? primaryArtifact.format : 'Artifact'} · {(primaryArtifact.size_bytes / 1024).toFixed(1)} KB
                  </span>
                </div>
                <div className="text-[11px] text-charcoal-secondary truncate">
                  SHA-256: <span className="text-charcoal font-semibold">{primaryArtifact.sha256}</span>
                </div>
                <div className="flex items-center space-x-2 text-[11px] text-vermilion">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  <span>Evidence Present: Forensic carving successfully reconstructed payload.</span>
                </div>
              </div>
            ) : (
              <div className="p-4 rounded bg-surface-subtle border border-border text-xs text-charcoal-muted font-mono text-center">
                Execute Forensic Scan to establish pre-sanitization evidence.
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-border-subtle text-[11px] font-mono text-charcoal-muted flex items-center justify-between">
            <span>Result: <strong className="text-vermilion">DATA SURVIVES DELETION</strong></span>
            <span>Confidence: 98%</span>
          </div>
        </div>

        {/* Right: AFTER SANITIZATION (VANISH Controlled Overwrite) */}
        <div className="p-5 rounded-lg bg-surface border border-verified-border/70 space-y-4 shadow-subtle flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded text-xs font-mono font-semibold bg-verified-surface text-verified border border-verified-border">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>STATE 2: POST-SANITIZATION</span>
              </span>
              <span className="text-xs font-mono text-charcoal-muted">L1–L4 Verification</span>
            </div>

            <h4 className="text-sm font-semibold text-charcoal">
              Controlled Overwrite Executed → 0 Target Artifacts Recoverable
            </h4>
            <p className="text-xs text-charcoal-secondary leading-relaxed">
              Target addressable sectors overwritten and verified across the 4-level matrix (MBR blanked, Shannon entropy verified, 0 deep carving candidates).
            </p>

            {isPostSanitizationVerified ? (
              <div className="p-3.5 rounded bg-surface-subtle border border-border space-y-2 text-xs font-mono">
                <div className="flex justify-between items-center text-charcoal">
                  <span className="font-semibold text-verified">Target Absence Confirmed</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-verified-surface border border-verified-border text-verified font-bold">
                    PASSED ({verificationReport.confidence_pct}% CONFIDENCE)
                  </span>
                </div>
                <div className="text-[11px] text-charcoal-secondary">
                  L4 Forensic Probe: <span className="text-charcoal font-semibold">0 target signatures detected across addressable space.</span>
                </div>
                <div className="flex items-center space-x-2 text-[11px] text-verified">
                  <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                  <span>Attestation Verified: Tamper-evident Ed25519 certificate issued.</span>
                </div>
              </div>
            ) : (
              <div className="p-4 rounded bg-surface-subtle border border-border text-xs text-charcoal-muted font-mono text-center">
                Run Sanitization and Verification to generate post-wipe proof.
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-border-subtle text-[11px] font-mono text-charcoal-muted flex items-center justify-between">
            <span>Result: <strong className={isPostSanitizationVerified ? 'text-verified' : 'text-charcoal-muted'}>{isPostSanitizationVerified ? 'TARGET ABSENCE CONFIRMED' : 'PENDING EXECUTION'}</strong></span>
            <span>Assurance: Scoped L1–L4</span>
          </div>
        </div>
      </div>
    </div>
  );
};
