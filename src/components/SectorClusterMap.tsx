import React from 'react';
import { HardDrive, Info } from 'lucide-react';

export type BlockState = 'scanned' | 'artifact' | 'overwritten' | 'zeroed' | 'unallocated' | 'protected';

interface BlockCell {
  id: number;
  offsetMb: number;
  state: BlockState;
  label: string;
}

interface SectorClusterMapProps {
  totalCapacityBytes: number;
  activeScopeBytes: number;
  scannedBytes?: number;
  artifactsCount?: number;
  isSanitized?: boolean;
  isProtected?: boolean;
}

export const SectorClusterMap: React.FC<SectorClusterMapProps> = ({
  totalCapacityBytes,
  activeScopeBytes,
  scannedBytes = 0,
  artifactsCount = 0,
  isSanitized = false,
  isProtected = false,
}) => {
  // 64 blocks grid (4 rows of 16 blocks)
  const TOTAL_BLOCKS = 64;
  const scopeRatio = Math.min(1, activeScopeBytes / (totalCapacityBytes || 1));
  const activeBlockCount = Math.max(1, Math.round(TOTAL_BLOCKS * scopeRatio));

  const blocks: BlockCell[] = Array.from({ length: TOTAL_BLOCKS }, (_, i) => {
    const offsetMb = ((i / TOTAL_BLOCKS) * (totalCapacityBytes / (1024 * 1024))).toFixed(1);
    const inActiveScope = i < activeBlockCount;

    let state: BlockState = 'unallocated';
    let label = `Block ${i} (~${offsetMb} MB)`;

    if (isProtected) {
      state = 'protected';
      label = `Protected OS Block ${i}`;
    } else if (isSanitized && inActiveScope) {
      state = 'overwritten';
      label = `Overwritten Block ${i} (0x00 / Pattern)`;
    } else if (artifactsCount > 0 && inActiveScope && (i === 1 || i === 4 || i === 8)) {
      state = 'artifact';
      label = `Carved Artifact Sector Cluster ${i}`;
    } else if (scannedBytes > 0 && inActiveScope) {
      state = 'scanned';
      label = `Scanned Sector Cluster ${i}`;
    } else if (inActiveScope) {
      state = 'zeroed';
      label = `Addressable Cluster ${i}`;
    }

    return {
      id: i,
      offsetMb: parseFloat(offsetMb),
      state,
      label,
    };
  });

  const stateColorMap: Record<BlockState, { bg: string; border: string; text: string }> = {
    scanned: { bg: 'bg-telemetry-surface', border: 'border-telemetry-border', text: 'text-telemetry' },
    artifact: { bg: 'bg-forensic-surface', border: 'border-forensic-border', text: 'text-forensic' },
    overwritten: { bg: 'bg-verified-surface', border: 'border-verified-border', text: 'text-verified' },
    zeroed: { bg: 'bg-surface-subtle', border: 'border-border', text: 'text-charcoal-muted' },
    unallocated: { bg: 'bg-surface-subtle/50', border: 'border-border-subtle', text: 'text-charcoal-faint' },
    protected: { bg: 'bg-vermilion-surface', border: 'border-vermilion-border', text: 'text-vermilion' },
  };

  return (
    <div className="p-5 bg-surface border border-border rounded-lg space-y-4 font-sans">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border pb-3">
        <div className="flex items-center space-x-2 text-charcoal">
          <HardDrive className="w-4 h-4 text-charcoal-muted" />
          <h4 className="text-xs font-semibold uppercase tracking-wider">
            Physical LBA Cluster Topology & Scope Map
          </h4>
        </div>
        <div className="flex items-center space-x-3 text-xs font-mono text-charcoal-secondary">
          <span>
            Total Media: <strong className="text-charcoal">{(totalCapacityBytes / (1024 * 1024 * 1024)).toFixed(2)} GiB</strong>
          </span>
          <span className="text-charcoal-faint">/</span>
          <span>
            Active Demo Scope: <strong className="text-vermilion">{(activeScopeBytes / (1024 * 1024)).toFixed(0)} MiB</strong>
          </span>
        </div>
      </div>

      {/* Cluster Grid */}
      <div className="grid grid-cols-16 gap-1.5 p-3 bg-surface-subtle/70 border border-border-subtle rounded">
        {blocks.map((b) => {
          const cfg = stateColorMap[b.state];
          return (
            <div
              key={b.id}
              title={b.label}
              className={`h-4 rounded-xs border transition-all ${cfg.bg} ${cfg.border} hover:scale-110 hover:shadow-xs cursor-default`}
            />
          );
        })}
      </div>

      {/* Map Legend */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-[11px] font-mono text-charcoal-secondary pt-1">
        <div className="flex items-center space-x-1.5">
          <div className="w-3 h-3 rounded-xs bg-forensic-surface border border-forensic-border" />
          <span>Carved Artifact</span>
        </div>
        <div className="flex items-center space-x-1.5">
          <div className="w-3 h-3 rounded-xs bg-verified-surface border border-verified-border" />
          <span>Sanitized / Overwritten</span>
        </div>
        <div className="flex items-center space-x-1.5">
          <div className="w-3 h-3 rounded-xs bg-telemetry-surface border border-telemetry-border" />
          <span>Active Scope Scan</span>
        </div>
        <div className="flex items-center space-x-1.5">
          <div className="w-3 h-3 rounded-xs bg-surface-subtle border border-border" />
          <span>Zeroed / Idle</span>
        </div>
        <div className="flex items-center space-x-1.5">
          <div className="w-3 h-3 rounded-xs bg-vermilion-surface border border-vermilion-border" />
          <span>Write-Locked OS</span>
        </div>
      </div>

      <div className="flex items-start space-x-2 text-[11px] text-charcoal-muted bg-surface-subtle p-2.5 rounded border border-border">
        <Info className="w-3.5 h-3.5 text-charcoal-muted shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <strong className="text-charcoal-secondary font-semibold">Scope Distinction:</strong> The active demonstration operates on the first {Math.round(activeScopeBytes / (1024 * 1024))} MiB region of physical media, containing partition headers and target forensic artifacts. Full media capacity is {(totalCapacityBytes / (1024 * 1024 * 1024)).toFixed(2)} GiB.
        </p>
      </div>
    </div>
  );
};
