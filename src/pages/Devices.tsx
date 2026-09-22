import React, { useEffect, useState } from 'react';
import { Device } from '../types';
import { fetchDevices } from '../services/api';
import { HardDrive, ShieldAlert, ShieldCheck, RefreshCw, Lock, Cpu, Database, CheckCircle2, AlertTriangle } from 'lucide-react';

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

  const getInterfaceLabel = (iface: Device['interface']): string => {
    if (typeof iface === 'string') return iface.toUpperCase();
    if (iface && typeof iface === 'object' && 'Unknown' in iface) return iface.Unknown;
    return 'UNKNOWN';
  };

  const getMediaTypeLabel = (media: Device['media_type']): string => {
    if (typeof media === 'string') return media;
    if (media && typeof media === 'object' && 'Unknown' in media) return media.Unknown;
    return 'Unknown';
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-[10px] font-mono font-bold tracking-widest text-telemetry uppercase bg-telemetry/10 px-2 py-0.5 rounded border border-telemetry/20">
              PHYSICAL & SYNTHETIC BUS
            </span>
            <span className="text-[10px] font-mono text-charcoal/50">WIN32_RAW_IO</span>
          </div>
          <h2 className="text-xl font-bold text-charcoal tracking-tight mt-1">Storage Targets & Bus Enumeration</h2>
          <p className="text-xs text-charcoal/60 mt-0.5">
            Real hardware devices, SCSI/USB bus endpoints, logical geometries, and deterministic simulation fixtures
          </p>
        </div>
        <button
          onClick={loadDevices}
          disabled={loading}
          className="flex items-center space-x-2 px-3.5 py-2 bg-white border border-border hover:bg-surface-elevated text-charcoal rounded-lg text-xs font-semibold shadow-subtle transition-all disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-telemetry ${loading ? 'animate-spin' : ''}`} />
          <span>Rescan Storage Bus</span>
        </button>
      </div>

      {/* Safety Invariant Notice */}
      <div className="p-4 rounded-xl bg-amber/5 border border-amber/20 flex items-start space-x-3 text-xs">
        <AlertTriangle className="w-4 h-4 text-amber shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-bold text-charcoal">Pre-Execution Kernel Safety Invariant</div>
          <div className="text-charcoal/70 leading-relaxed font-sans">
            VANISH applies an immutable 11-point safety lock over any disk hosting active operating system partitions, system volume information, or EFI boot flags. Target destruction commands are physically inhibited for system drives.
          </div>
        </div>
      </div>

      {/* Device List */}
      <div className="space-y-4">
        {devices.map((device) => {
          const isProtected = device.boot_device || device.system_disk;
          return (
            <div
              key={device.stable_id}
              className={`p-6 rounded-xl border bg-white shadow-subtle transition-all ${
                isProtected
                  ? 'border-vermilion/30 ring-1 ring-vermilion/10'
                  : 'border-border hover:border-telemetry/40'
              }`}
            >
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div className="flex items-start space-x-4">
                  <div className={`p-3 rounded-lg border ${
                    isProtected 
                      ? 'bg-vermilion/10 text-vermilion border-vermilion/20' 
                      : device.is_simulated
                      ? 'bg-amber/10 text-amber border-amber/20'
                      : 'bg-telemetry/10 text-telemetry border-telemetry/20'
                  }`}>
                    {device.is_simulated ? <Database className="w-6 h-6" /> : <HardDrive className="w-6 h-6" />}
                  </div>

                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <h4 className="text-base font-bold text-charcoal tracking-tight">{device.model}</h4>
                      
                      {device.is_simulated ? (
                        <span className="inline-flex items-center px-2 py-0.5 rounded bg-amber/10 text-amber text-[10px] font-mono font-bold uppercase tracking-wider border border-amber/30">
                          Synthetic Lab Fixture
                        </span>
                      ) : (
                        <span className="inline-flex items-center px-2 py-0.5 rounded bg-surface-elevated text-charcoal/70 text-[10px] font-mono font-bold uppercase border border-border">
                          Physical Hardware
                        </span>
                      )}

                      {isProtected ? (
                        <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded bg-vermilion/10 text-vermilion text-xs font-bold border border-vermilion/30 font-mono">
                          <Lock className="w-3 h-3" />
                          <span>HOST SYSTEM DISK (LOCKED)</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded bg-verified/10 text-verified text-xs font-bold border border-verified/30 font-mono">
                          <CheckCircle2 className="w-3 h-3" />
                          <span>SANITIZATION TARGET ELIGIBLE</span>
                        </span>
                      )}
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3 pt-2 text-xs font-mono text-charcoal/70">
                      <div>
                        <span className="text-[10px] text-charcoal/40 uppercase block">Device Path</span>
                        <strong className="text-charcoal font-semibold">{device.path}</strong>
                      </div>
                      <div>
                        <span className="text-[10px] text-charcoal/40 uppercase block">Serial Number</span>
                        <strong className="text-charcoal font-semibold">{device.serial || 'N/A'}</strong>
                      </div>
                      <div>
                        <span className="text-[10px] text-charcoal/40 uppercase block">Bus Interface</span>
                        <strong className="text-telemetry font-semibold">{getInterfaceLabel(device.interface)}</strong>
                      </div>
                      <div>
                        <span className="text-[10px] text-charcoal/40 uppercase block">Media Type</span>
                        <strong className="text-charcoal font-semibold">{getMediaTypeLabel(device.media_type)}</strong>
                      </div>
                      <div>
                        <span className="text-[10px] text-charcoal/40 uppercase block">Total Capacity</span>
                        <strong className="text-charcoal font-semibold">{formatBytes(device.capacity_bytes)}</strong>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="flex flex-col items-start lg:items-end justify-center shrink-0 border-t lg:border-t-0 pt-3 lg:pt-0 border-border">
                  {isProtected ? (
                    <div className="text-xs text-vermilion font-semibold px-3 py-1.5 bg-vermilion/5 rounded-lg border border-vermilion/20 flex items-center space-x-1.5">
                      <ShieldAlert className="w-4 h-4" />
                      <span>Write Protected</span>
                    </div>
                  ) : (
                    <div className="text-xs text-verified font-semibold px-3 py-1.5 bg-verified/5 rounded-lg border border-verified/20 flex items-center space-x-1.5 font-mono">
                      <ShieldCheck className="w-4 h-4" />
                      <span>Verified Disposable</span>
                    </div>
                  )}
                  <span className="text-[10px] font-mono text-charcoal/40 mt-1">
                    Sector: {device.logical_block_size}B (L) / {device.physical_block_size}B (P)
                  </span>
                </div>
              </div>

              {/* Hardware Capabilities */}
              <div className="mt-4 pt-3 border-t border-border flex flex-wrap gap-2 items-center">
                <span className="text-[11px] font-mono text-charcoal/50 uppercase tracking-wider">
                  Hardware Capabilities:
                </span>
                {device.capabilities && device.capabilities.length > 0 ? (
                  device.capabilities.map((cap) => (
                    <span
                      key={cap}
                      className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-surface-elevated text-charcoal/80 text-[11px] font-mono border border-border"
                    >
                      <Cpu className="w-3 h-3 text-telemetry" />
                      <span>{cap}</span>
                    </span>
                  ))
                ) : (
                  <span className="text-xs font-mono text-charcoal/40 italic">No low-level vendor primitives reported</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
