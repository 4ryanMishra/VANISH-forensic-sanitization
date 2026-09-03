import React, { useEffect, useState } from 'react';
import { Device } from '../types';
import { fetchDevices } from '../services/api';
import { HardDrive, ShieldAlert, ShieldCheck, RefreshCw, Lock, Cpu } from 'lucide-react';

export const Devices: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  const loadDevices = async () => {
    setLoading(true);
    const data = await fetchDevices();
    setDevices(data);
    setLoading(false);
  };

  useEffect(() => {
    loadDevices();
  }, []);

  const formatBytes = (bytes: number) => {
    if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(2)} TB`;
    if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} GB`;
    if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(2)} MB`;
    return `${bytes} B`;
  };

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xl font-bold text-white">Storage Devices & Targets</h3>
          <p className="text-xs text-gray-400">Enumerated hardware and virtual storage abstraction layer</p>
        </div>
        <button
          onClick={loadDevices}
          disabled={loading}
          className="flex items-center space-x-2 px-3 py-2 bg-surface border border-gray-700 hover:bg-surface-highlight text-gray-200 rounded-lg text-sm transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          <span>Rescan Bus</span>
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {devices.map((device) => {
          const isProtected = device.boot_device || device.system_disk;
          return (
            <div
              key={device.stable_id}
              className={`p-6 rounded-xl border transition-all ${
                isProtected
                  ? 'bg-surface border-red-900/30'
                  : 'bg-surface border-gray-800 hover:border-blue-500/30'
              }`}
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="flex items-start space-x-4">
                  <div className={`p-3 rounded-lg ${isProtected ? 'bg-red-500/10 text-red-400' : 'bg-blue-500/10 text-blue-400'}`}>
                    <HardDrive className="w-6 h-6" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-3">
                      <h4 className="text-base font-bold text-white">{device.model}</h4>
                      {device.is_simulated && (
                        <span className="inline-flex items-center px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 text-[10px] font-bold uppercase tracking-wider border border-amber-500/30">
                          Simulation Mode
                        </span>
                      )}
                      {isProtected && (
                        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 text-xs font-semibold border border-red-500/30">
                          <Lock className="w-3 h-3" />
                          <span>HOST SYSTEM DISK</span>
                        </span>
                      )}
                      {!isProtected && (
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 text-xs font-medium border border-emerald-500/20">
                          Disposable / Lab Target
                        </span>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-400 mt-2 font-mono">
                      <span>Path: <strong className="text-gray-200">{device.path}</strong></span>
                      <span>Serial: <strong className="text-gray-200">{device.serial}</strong></span>
                      <span>Interface: <strong className="text-gray-200">{typeof device.interface === 'string' ? device.interface : 'Unknown'}</strong></span>
                      <span>Capacity: <strong className="text-blue-400">{formatBytes(device.capacity_bytes)}</strong></span>
                      <span>Block Size: <strong className="text-gray-200">{device.logical_block_size}B / {device.physical_block_size}B</strong></span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  {isProtected ? (
                    <div className="text-xs text-red-400 font-semibold px-3 py-2 bg-red-950/40 rounded-lg border border-red-800/40 flex items-center space-x-1.5">
                      <ShieldAlert className="w-4 h-4" />
                      <span>Write Protected</span>
                    </div>
                  ) : (
                    <div className="text-xs text-emerald-400 font-semibold px-3 py-2 bg-emerald-950/40 rounded-lg border border-emerald-800/40 flex items-center space-x-1.5">
                      <ShieldCheck className="w-4 h-4" />
                      <span>Armed & Ready</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Detected Capabilities */}
              <div className="mt-4 pt-4 border-t border-gray-800 flex flex-wrap gap-2 items-center">
                <span className="text-xs text-gray-500 font-medium">Hardware Capabilities:</span>
                {device.capabilities.map((cap) => (
                  <span
                    key={cap}
                    className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-surface-highlight text-gray-300 text-xs font-mono border border-gray-700"
                  >
                    <Cpu className="w-3 h-3 text-blue-400" />
                    <span>{cap}</span>
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
