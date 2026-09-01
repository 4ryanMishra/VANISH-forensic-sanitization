import React from 'react';
import { ShieldCheck, Cpu } from 'lucide-react';

interface HeaderProps {
  title: string;
  subtitle: string;
}

export const Header: React.FC<HeaderProps> = ({ title, subtitle }) => {
  return (
    <header className="h-16 border-b border-gray-800 bg-surface/50 backdrop-blur px-8 flex items-center justify-between">
      <div>
        <h2 className="text-lg font-semibold text-white tracking-wide">{title}</h2>
        <p className="text-xs text-gray-400">{subtitle}</p>
      </div>

      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-surface-highlight border border-gray-700/60 text-xs">
          <Cpu className="w-3.5 h-3.5 text-blue-400" />
          <span className="text-gray-300">Engine: Native Rust</span>
        </div>

        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-emerald-950/40 border border-emerald-500/30 text-xs text-emerald-400">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Attestation: SHA-256 Chained</span>
        </div>
      </div>
    </header>
  );
};
