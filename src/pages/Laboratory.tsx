import React, { useState } from 'react';
import { FlaskConical, Layers, CheckCircle, BarChart3, Database } from 'lucide-react';

interface EntropySample {
  sector: number;
  entropy: number;
  label: string;
}

export const Laboratory: React.FC = () => {
  const [mounted, setMounted] = useState<boolean>(false);
  const [runningEntropy, setRunningEntropy] = useState<boolean>(false);
  const [entropyData, setEntropyData] = useState<EntropySample[]>([]);

  const handleMount = () => {
    setMounted(true);
  };

  const handleRunEntropy = () => {
    setRunningEntropy(true);
    setTimeout(() => {
      // Generate synthetic entropy profile across 16 sample sectors
      const samples: EntropySample[] = [
        { sector: 0, entropy: 0.85, label: 'MBR Sector (0x000)' },
        { sector: 2048, entropy: 7.84, label: 'JPEG Chunk (0x100000)' },
        { sector: 2080, entropy: 7.89, label: 'JPEG Payload' },
        { sector: 3000, entropy: 0.00, label: 'Zeroed Cluster Slack' },
        { sector: 4096, entropy: 7.21, label: 'PDF Fragment Head (0x200000)' },
        { sector: 4104, entropy: 3.40, label: 'Foreign Interleaved Data' },
        { sector: 4112, entropy: 7.15, label: 'PDF Fragment Tail (0x202000)' },
        { sector: 5000, entropy: 0.00, label: 'Unallocated Free Space' },
        { sector: 6144, entropy: 7.92, label: 'PNG Chunk Array (0x300000)' },
        { sector: 6200, entropy: 0.00, label: 'Zeroed Trailing Space' },
      ];
      setEntropyData(samples);
      setRunningEntropy(false);
    }, 600);
  };

  return (
    <div className="p-8 space-y-6">
      <div>
        <h3 className="text-xl font-bold text-white">Virtual Laboratory & Hardware Simulator</h3>
        <p className="text-xs text-gray-400">Safe sandbox for simulated carving, block-level overwriting, and entropy validation</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Virtual Disk Fixtures Card */}
        <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3 text-blue-400">
              <Layers className="w-6 h-6" />
              <h4 className="font-bold text-white text-base">Virtual Disk Fixtures</h4>
            </div>
            {mounted && (
              <span className="flex items-center space-x-1 text-xs text-emerald-400 font-mono">
                <CheckCircle className="w-3.5 h-3.5" />
                <span>Mounted</span>
              </span>
            )}
          </div>
          <p className="text-xs text-gray-400 leading-relaxed">
            Synthetic raw virtual disk image (`vanish_lab_image.img`, 16 MB) containing injected contiguous JPEGs, fragmented PDFs with 8KB gaps, and PNGs for deterministic benchmarking.
          </p>
          <button
            onClick={handleMount}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold transition-colors"
          >
            {mounted ? 'Remount Synthetic Virtual Disk' : 'Mount Synthetic Virtual Disk'}
          </button>

          {mounted && (
            <div className="mt-4 p-4 rounded-lg bg-black/40 border border-gray-800 space-y-2 text-xs font-mono">
              <div className="text-gray-300 font-bold flex items-center space-x-2">
                <Database className="w-4 h-4 text-blue-400" />
                <span>Target: test-data/virtual-disks/vanish_lab_image.img</span>
              </div>
              <div className="text-gray-400">Partition 1: Start LBA 2048, 15 MB FAT32 (Bootable)</div>
              <div className="text-gray-400">Injected Artifact 1: JPEG at 0x100000 (16.4 KB, Contiguous)</div>
              <div className="text-gray-400">Injected Artifact 2: Fragmented PDF at 0x200000 (Gap: 8 KB)</div>
              <div className="text-gray-400">Injected Artifact 3: PNG at 0x300000 (32.8 KB, Valid CRC)</div>
            </div>
          )}
        </div>

        {/* Entropy Profiler Card */}
        <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-4">
          <div className="flex items-center space-x-3 text-purple-400">
            <FlaskConical className="w-6 h-6" />
            <h4 className="font-bold text-white text-base">Shannon Entropy & Transition Profiler</h4>
          </div>
          <p className="text-xs text-gray-400 leading-relaxed">
            Real-time Shannon entropy mapping across LBA blocks ($0.00$ bits/byte for uniform zeroes, $\approx 7.20 - 7.99$ for compressed/encrypted content, $\approx 3.40$ for text/slack).
          </p>
          <button
            onClick={handleRunEntropy}
            disabled={runningEntropy}
            className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold transition-colors"
          >
            {runningEntropy ? 'Computing Sector Entropy...' : 'Run Sector Entropy Profiler'}
          </button>
        </div>
      </div>

      {/* Entropy Visualization Graph */}
      {entropyData.length > 0 && (
        <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2 text-purple-400">
              <BarChart3 className="w-5 h-5" />
              <h4 className="text-sm font-bold text-white uppercase tracking-wider">
                Sector Entropy Distribution ($H = -\sum p_i \log_2 p_i$)
              </h4>
            </div>
            <span className="text-xs text-gray-400 font-mono">Max Theoretical Entropy: 8.00 bits/byte</span>
          </div>

          <div className="space-y-3">
            {entropyData.map((sample, idx) => (
              <div key={idx} className="space-y-1">
                <div className="flex justify-between text-xs font-mono">
                  <span className="text-gray-300 font-semibold">{sample.label} (Sector {sample.sector})</span>
                  <span className={sample.entropy > 7.0 ? 'text-purple-400 font-bold' : sample.entropy === 0 ? 'text-gray-500' : 'text-blue-400'}>
                    {sample.entropy.toFixed(2)} bits/byte
                  </span>
                </div>
                <div className="w-full bg-gray-900 rounded-full h-2 overflow-hidden">
                  <div
                    className={`h-2 rounded-full transition-all duration-500 ${
                      sample.entropy > 7.0
                        ? 'bg-purple-500'
                        : sample.entropy > 3.0
                        ? 'bg-blue-500'
                        : 'bg-gray-700'
                    }`}
                    style={{ width: `${(sample.entropy / 8.0) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
