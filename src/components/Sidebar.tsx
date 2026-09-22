import React from 'react';
import {
  LayoutDashboard,
  HardDrive,
  Trash2,
  FileSearch,
  CheckCircle2,
  ScrollText,
  FileText,
  FlaskConical,
  Shield,
  Activity
} from 'lucide-react';

export type PageId =
  | 'dashboard'
  | 'devices'
  | 'sanitization'
  | 'forensics'
  | 'verification'
  | 'audit'
  | 'reports'
  | 'lab';

interface SidebarProps {
  activePage: PageId;
  onSelectPage: (page: PageId) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activePage, onSelectPage }) => {
  const workflowItems = [
    { id: 'dashboard' as PageId, label: 'Workstation Overview', icon: LayoutDashboard, tag: '01' },
    { id: 'devices' as PageId, label: 'Device & Bus Manager', icon: HardDrive, tag: '02' },
    { id: 'forensics' as PageId, label: 'Forensic Recovery', icon: FileSearch, tag: '03', accent: 'forensic' },
    { id: 'sanitization' as PageId, label: 'Sanitization Engine', icon: Trash2, tag: '04', accent: 'vermilion' },
    { id: 'verification' as PageId, label: 'L1–L4 Verification', icon: CheckCircle2, tag: '05', accent: 'verified' },
    { id: 'audit' as PageId, label: 'Tamper-Evident Ledger', icon: ScrollText, tag: '06' },
    { id: 'reports' as PageId, label: 'Attestation Reports', icon: FileText, tag: '07' },
  ];

  const toolsItems = [
    { id: 'lab' as PageId, label: 'Virtual Lab & Sandbox', icon: FlaskConical, tag: 'SIM' },
  ];

  return (
    <aside className="w-64 bg-surface border-r border-border flex flex-col flex-shrink-0 select-none font-sans">
      {/* Brand Header */}
      <div className="p-5 border-b border-border bg-surface-subtle/50 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="w-7 h-7 rounded bg-charcoal text-white flex items-center justify-center font-mono font-bold text-xs tracking-tighter">
            V▪
          </div>
          <div>
            <div className="flex items-center space-x-1.5">
              <span className="font-bold tracking-tight text-charcoal text-base font-sans">VANISH</span>
              <span className="text-[10px] font-mono text-charcoal-muted uppercase tracking-widest px-1 py-0.2 bg-border-subtle rounded">Core</span>
            </div>
            <p className="text-[11px] text-charcoal-muted font-mono leading-none mt-0.5">Forensic Workstation</p>
          </div>
        </div>
      </div>

      {/* Main Navigation */}
      <div className="flex-1 overflow-y-auto p-3 space-y-6">
        <div>
          <div className="px-3 pb-2 text-[10px] font-mono uppercase tracking-wider text-charcoal-muted font-semibold flex items-center justify-between">
            <span>Investigation Lifecycle</span>
            <Activity className="w-3 h-3 text-charcoal-faint" />
          </div>
          <nav className="space-y-0.5">
            {workflowItems.map((item) => {
              const Icon = item.icon;
              const isActive = activePage === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectPage(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-charcoal text-white font-semibold shadow-subtle'
                      : 'text-charcoal-secondary hover:text-charcoal hover:bg-surface-hover'
                  }`}
                >
                  <div className="flex items-center space-x-2.5">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-charcoal-muted'}`} />
                    <span>{item.label}</span>
                  </div>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${
                      isActive
                        ? 'bg-white/20 text-white'
                        : 'text-charcoal-faint bg-surface-subtle'
                    }`}
                  >
                    {item.tag}
                  </span>
                </button>
              );
            })}
          </nav>
        </div>

        <div>
          <div className="px-3 pb-2 text-[10px] font-mono uppercase tracking-wider text-charcoal-muted font-semibold">
            Simulation & Diagnostics
          </div>
          <nav className="space-y-0.5">
            {toolsItems.map((item) => {
              const Icon = item.icon;
              const isActive = activePage === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectPage(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-charcoal text-white font-semibold shadow-subtle'
                      : 'text-charcoal-secondary hover:text-charcoal hover:bg-surface-hover'
                  }`}
                >
                  <div className="flex items-center space-x-2.5">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-charcoal-muted'}`} />
                    <span>{item.label}</span>
                  </div>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${
                      isActive ? 'bg-white/20 text-white' : 'text-charcoal-faint bg-surface-subtle'
                    }`}
                  >
                    {item.tag}
                  </span>
                </button>
              );
            })}
          </nav>
        </div>
      </div>

      {/* Safety Gate Indicator Widget */}
      <div className="p-3 m-3 rounded border border-border bg-surface-subtle space-y-1.5 text-xs font-sans">
        <div className="flex items-center space-x-2 text-verified-dark font-semibold text-[11px]">
          <Shield className="w-3.5 h-3.5 text-verified" />
          <span>Safety Invariants Active</span>
        </div>
        <p className="text-[11px] text-charcoal-muted leading-tight font-mono">
          Host boot & system disks write-locked by 2-stage kernel safety gate.
        </p>
      </div>
    </aside>
  );
};
