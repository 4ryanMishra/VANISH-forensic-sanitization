import React from 'react';
import { FlaskConical, Layers } from 'lucide-react';

export const Laboratory: React.FC = () => {
  return (
    <div className="p-8 space-y-6">
      <div>
        <h3 className="text-xl font-bold text-white">Virtual Laboratory & Hardware Simulator</h3>
        <p className="text-xs text-gray-400">Safe sandbox for simulated carving, block-level overwriting, and entropy validation</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-4">
          <div className="flex items-center space-x-3 text-blue-400">
            <Layers className="w-6 h-6" />
            <h4 className="font-bold text-white text-base">Virtual Disk Fixtures</h4>
          </div>
          <p className="text-xs text-gray-400 leading-relaxed">
            Generate synthetic FAT32, exFAT, and NTFS raw virtual disk images containing injected file fragments, slack space remnants, and deleted file headers for reproducible benchmarking.
          </p>
          <button className="px-4 py-2 bg-surface-highlight hover:bg-gray-800 border border-gray-700 text-xs font-semibold text-gray-200 rounded-lg">
            Mount Synthetic Virtual Disk
          </button>
        </div>

        <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-4">
          <div className="flex items-center space-x-3 text-purple-400">
            <FlaskConical className="w-6 h-6" />
            <h4 className="font-bold text-white text-base">Entropy & Inversion Profiler</h4>
          </div>
          <p className="text-xs text-gray-400 leading-relaxed">
            Real-time Shannon entropy graphing across LBA chunks (0.00 for uniform zeroes, ~7.99 for compressed/encrypted content, ~3.50 for plain text).
          </p>
          <button className="px-4 py-2 bg-surface-highlight hover:bg-gray-800 border border-gray-700 text-xs font-semibold text-gray-200 rounded-lg">
            Run Real-Time Entropy Scan
          </button>
        </div>
      </div>
    </div>
  );
};
