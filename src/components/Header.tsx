import React from 'react';
import { Cpu, ShieldCheck } from 'lucide-react';

interface HeaderProps {
  title: string;
  subtitle: string;
  activeTargetDesc?: string;
}

export const Header: React.FC<HeaderProps> = ({ title, subtitle, activeTargetDesc }) => {
  return (
    <header className="h-16 border-b border-border bg-surface px-8 flex items-center justify-between select-none font-sans shrink-0">
      <div className="flex items-center space-x-4">
        <div>
          <h2 className="text-sm font-semibold text-charcoal tracking-tight">{title}</h2>
          <p className="text-xs text-charcoal-muted font-mono">{subtitle}</p>
        </div>
      </div>

      <div className="flex items-center space-x-3">
        {activeTargetDesc && (
          <div className="hidden md:flex items-center space-x-1.5 px-2.5 py-1 rounded bg-surface-subtle border border-border text-xs font-mono">
            <span className="text-charcoal-muted">Target:</span>
            <span className="font-semibold text-charcoal">{activeTargetDesc}</span>
          </div>
        )}

        <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-surface-subtle border border-border text-xs font-mono text-charcoal-secondary">
          <Cpu className="w-3.5 h-3.5 text-telemetry" />
          <span>Rust Native Core</span>
        </div>

        <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-verified-surface border border-verified-border text-xs font-mono text-verified-dark font-semibold">
          <ShieldCheck className="w-3.5 h-3.5 text-verified" />
          <span>SHA-256 Chain</span>
        </div>
      </div>
    </header>
  );
};
