import React from 'react';
import {
  LayoutDashboard,
  HardDrive,
  Trash2,
  FileSearch,
  CheckCircle2,
  ShieldAlert,
  FileText,
  FlaskConical
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
  const navItems = [
    { id: 'dashboard' as PageId, label: 'Dashboard', icon: LayoutDashboard },
    { id: 'devices' as PageId, label: 'Device Manager', icon: HardDrive },
    { id: 'sanitization' as PageId, label: 'Sanitization', icon: Trash2 },
    { id: 'forensics' as PageId, label: 'Forensic Recovery', icon: FileSearch },
    { id: 'verification' as PageId, label: 'L1–L4 Verification', icon: CheckCircle2 },
    { id: 'audit' as PageId, label: 'Tamper-Evident Audit', icon: ShieldAlert },
    { id: 'reports' as PageId, label: 'Attestation & Reports', icon: FileText },
    { id: 'lab' as PageId, label: 'Virtual Lab & Sim', icon: FlaskConical },
  ];

  return (
    <aside className="w-64 bg-surface border-r border-gray-800 flex flex-col flex-shrink-0">
      {/* Brand Header */}
      <div className="p-5 border-b border-gray-800 flex items-center space-x-3">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center font-bold text-white shadow-lg shadow-blue-500/20">
          V
        </div>
        <div>
          <h1 className="font-bold tracking-wider text-white text-base">VANISH</h1>
          <p className="text-xs text-gray-400 font-mono">v0.1.0-alpha</p>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="p-3 space-y-1 flex-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activePage === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectPage(item.id)}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-surface-highlight'
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? 'text-blue-400' : 'text-gray-400'}`} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Security & Safety Status Widget */}
      <div className="p-4 m-3 rounded-lg bg-surface-highlight/60 border border-gray-800 text-xs">
        <div className="flex items-center space-x-2 text-emerald-400 font-semibold mb-1">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          <span>Safety Invariants Active</span>
        </div>
        <p className="text-gray-400">Boot & System disk writes strictly blocked.</p>
      </div>
    </aside>
  );
};
