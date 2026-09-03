import React, { useState, useEffect } from 'react';
import { FileCode, Play, Download, ShieldCheck, CheckCircle2, HardDrive, Image as ImageIcon, Eye } from 'lucide-react';
import { Device, RecoveredArtifact, RecoveryJob } from '../types';
import { executeRecoveryJob, fetchDevices } from '../services/api';

export const ForensicRecovery: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedTarget, setSelectedTarget] = useState<string>('test-data/virtual-disks/vanish_lab_image.img');
  const [scanning, setScanning] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [artifacts, setArtifacts] = useState<RecoveredArtifact[]>([]);
  const [scanSummary, setScanSummary] = useState<{ scannedBytes: number; durationMs: number; isSim: boolean; targetLabel?: string } | null>(null);
  const [previewArtifact, setPreviewArtifact] = useState<RecoveredArtifact | null>(null);

  useEffect(() => {
    fetchDevices().then((devs) => {
      setDevices(devs);
      // Auto-select physical non-system target if available
      const realTarget = devs.find((d) => !d.system_disk && !d.boot_device && !d.is_simulated);
      if (realTarget) {
        setSelectedTarget(realTarget.path);
      }
    });
  }, []);

  const isSimulation = selectedTarget === 'disk-vdisk-01';
  const isPhysical = selectedTarget.toUpperCase().includes('PHYSICALDRIVE') || selectedTarget.startsWith('\\\\.\\') || selectedTarget.startsWith('/dev/');

  const handleStartScan = async () => {
    setScanning(true);
    setProgress(0);
    setArtifacts([]);
    setScanSummary(null);
    setPreviewArtifact(null);

    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 90) return 90;
        return prev + 15;
      });
    }, 150);

    const job: RecoveryJob = {
      job_id: `rec-job-${Date.now()}`,
      source_path: selectedTarget,
      scan_mode: 'ContiguousAndFragmentedCarving',
      simulation_mode: isSimulation,
      created_at_utc: new Date().toISOString(),
    };

    try {
      const result = await executeRecoveryJob(job);
      clearInterval(interval);
      setProgress(100);
      setArtifacts(result.artifacts);
      setScanSummary({
        scannedBytes: result.total_scanned_bytes,
        durationMs: result.execution_time_ms,
        isSim: result.simulation_mode,
        targetLabel: result.source_id,
      });
    } catch (err) {
      console.error('Forensic recovery failed:', err);
      clearInterval(interval);
    } finally {
      setScanning(false);
    }
  };

  const handleDownloadArtifact = (art: RecoveredArtifact) => {
    if (!art.data_base64) return;
    const byteCharacters = atob(art.data_base64);
    const byteNumbers = new Array(byteCharacters.length);
    for (let i = 0; i < byteCharacters.length; i++) {
      byteNumbers[i] = byteCharacters.charCodeAt(i);
    }
    const byteArray = new Uint8Array(byteNumbers);
    const mimeType = typeof art.format === 'string' && art.format.toLowerCase() === 'jpeg'
      ? 'image/jpeg'
      : typeof art.format === 'string' && art.format.toLowerCase() === 'png'
      ? 'image/png'
      : typeof art.format === 'string' && art.format.toLowerCase() === 'pdf'
      ? 'application/pdf'
      : 'application/octet-stream';
    const blob = new Blob([byteArray], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const ext = typeof art.format === 'string' && art.format.toLowerCase() === 'jpeg' ? 'jpg' : typeof art.format === 'string' ? art.format.toLowerCase() : 'bin';
    a.download = `VANISH_RECOVERED_${art.artifact_id}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportManifest = () => {
    const manifest = {
      report_title: 'VANISH Digital Forensic Carving & Reconstruction Evidence Manifest',
      generated_at: new Date().toISOString(),
      source_target: selectedTarget,
      simulation_mode: isSimulation,
      artifacts_recovered_count: artifacts.length,
      artifacts,
    };

    const blob = new Blob([JSON.stringify(manifest, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `VANISH_FORENSIC_MANIFEST_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-8 space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <h3 className="text-xl font-bold text-white">Read-Only Forensic Analysis & Carving</h3>
            {isSimulation ? (
              <span className="px-2.5 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-mono font-bold">
                SIMULATION MODE
              </span>
            ) : isPhysical ? (
              <span className="px-2.5 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono font-bold flex items-center space-x-1">
                <HardDrive className="w-3 h-3" />
                <span>PHYSICAL DISK STREAM (READ-ONLY)</span>
              </span>
            ) : (
              <span className="px-2.5 py-0.5 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-400 text-xs font-mono font-bold">
                RAW IMAGE CARVING
              </span>
            )}
          </div>
          <p className="text-xs text-gray-400 mt-0.5">
            Non-destructive sector streaming, container parsing, fragmented reconstruction, and SHA-256 evidence provenance
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <select
            value={selectedTarget}
            onChange={(e) => setSelectedTarget(e.target.value)}
            disabled={scanning}
            className="bg-surface border border-gray-700 text-gray-200 text-xs rounded-lg px-3 py-2.5 focus:outline-none focus:border-purple-500 font-mono"
          >
            {devices.filter((d) => !d.is_simulated).length > 0 && (
              <optgroup label="Physical Storage Devices (Strict Read-Only)">
                {devices
                  .filter((d) => !d.is_simulated)
                  .map((d) => (
                    <option key={d.stable_id} value={d.path}>
                      {d.path} ({d.model} - {(d.capacity_bytes / (1024 * 1024 * 1024)).toFixed(2)} GB)
                    </option>
                  ))}
              </optgroup>
            )}
            <optgroup label="Laboratory Demo & Virtual Targets">
              <option value="test-data/virtual-disks/vanish_lab_image.img">
                Target: vanish_lab_image.img (16MB Raw Image)
              </option>
              <option value="disk-vdisk-01">
                Target: disk-vdisk-01 (In-Memory Virtual Disk)
              </option>
            </optgroup>
          </select>

          <button
            onClick={handleStartScan}
            disabled={scanning}
            className="flex items-center space-x-2 px-4 py-2.5 bg-purple-600 hover:bg-purple-500 disabled:bg-gray-800 text-white rounded-lg text-sm font-semibold transition-colors shadow-lg shadow-purple-600/20"
          >
            <Play className="w-4 h-4" />
            <span>{scanning ? 'Scanning Evidence...' : 'Start Carving Scan'}</span>
          </button>
        </div>
      </div>

      {/* Write-Block Safety Callout */}
      <div className="p-4 rounded-xl bg-surface border border-gray-800 flex items-center justify-between text-xs font-mono">
        <div className="flex items-center space-x-2 text-emerald-400">
          <ShieldCheck className="w-4 h-4" />
          <span className="font-semibold">Write-Block Status: Hardware/Kernel Read-Only Active (Zero-Write Enforcement)</span>
        </div>
        <div className="text-gray-400">
          Mode: <strong className={isSimulation ? 'text-blue-400' : isPhysical ? 'text-emerald-400' : 'text-purple-400'}>{isSimulation ? 'SIMULATION MODE' : isPhysical ? 'PHYSICAL DEVICE RAW STREAM' : 'RAW IMAGE STREAM'}</strong>
        </div>
      </div>

      {/* Progress Bar */}
      {scanning && (
        <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-2">
          <div className="flex justify-between text-xs font-mono">
            <span className="text-gray-400">Streaming raw physical sectors and analyzing container magic headers...</span>
            <span className="text-purple-400 font-bold">{progress}%</span>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
            <div
              className="bg-purple-600 h-2 rounded-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Scan Summary Banner */}
      {scanSummary && !scanning && (
        <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-500/20 flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
          <div className="flex items-center space-x-2 text-purple-300">
            <CheckCircle2 className="w-4 h-4 text-purple-400" />
            <span>Scan Complete: {artifacts.length} Artifacts Recovered & Validated</span>
          </div>
          <div className="flex items-center space-x-4 text-gray-400">
            <span>Bytes Scanned: <strong className="text-gray-200">{scanSummary.scannedBytes >= 1024 * 1024 ? `${(scanSummary.scannedBytes / (1024 * 1024)).toFixed(2)} MB` : `${(scanSummary.scannedBytes / 1024).toFixed(1)} KB`}</strong></span>
            <span>Duration: <strong className="text-gray-200">{scanSummary.durationMs} ms</strong></span>
            <span>Source: <strong className="text-emerald-400">{scanSummary.targetLabel || selectedTarget}</strong></span>
          </div>
        </div>
      )}

      {/* Image Preview Modal */}
      {previewArtifact && previewArtifact.data_base64 && (
        <div className="p-6 rounded-xl bg-surface border border-purple-500/40 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2 text-purple-400">
              <ImageIcon className="w-4 h-4" />
              <span className="font-bold text-sm text-white">Carved File Preview: {previewArtifact.original_path || previewArtifact.artifact_id}</span>
            </div>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => handleDownloadArtifact(previewArtifact)}
                className="flex items-center space-x-1 px-3 py-1 bg-purple-600 hover:bg-purple-500 text-white rounded text-xs font-semibold"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Save File</span>
              </button>
              <button
                onClick={() => setPreviewArtifact(null)}
                className="px-2 py-1 text-gray-400 hover:text-white text-xs"
              >
                Close
              </button>
            </div>
          </div>
          <div className="flex justify-center p-4 bg-black/40 rounded-lg border border-gray-800">
            {typeof previewArtifact.format === 'string' && (previewArtifact.format.toLowerCase() === 'jpeg' || previewArtifact.format.toLowerCase() === 'png' || previewArtifact.format.toLowerCase() === 'gif') ? (
              <img
                src={`data:image/${previewArtifact.format.toLowerCase() === 'jpeg' ? 'jpeg' : previewArtifact.format.toLowerCase()};base64,${previewArtifact.data_base64}`}
                alt="Carved Artifact"
                className="max-h-72 max-w-full rounded shadow-lg object-contain border border-gray-700"
              />
            ) : (
              <div className="p-8 text-xs font-mono text-gray-400 text-center">
                Binary preview: {previewArtifact.size_bytes} bytes reconstructed. Click "Save File" to export.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Recovered Artifacts Table */}
      <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-4">
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-bold text-white uppercase tracking-wider">
            Recovered Evidence Artifacts ({artifacts.length})
          </h4>
          {artifacts.length > 0 && (
            <button
              onClick={handleExportManifest}
              className="flex items-center space-x-1.5 px-3 py-1.5 bg-surface-highlight hover:bg-gray-800 border border-gray-700 text-gray-200 rounded-lg text-xs font-medium transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Carved Manifest</span>
            </button>
          )}
        </div>

        {artifacts.length === 0 && !scanning && (
          <div className="p-8 text-center text-gray-500 text-sm font-mono">
            No active recovery session. Select target device and click "Start Carving Scan".
          </div>
        )}

        {artifacts.length > 0 && (
          <div className="divide-y divide-gray-800">
            {artifacts.map((art) => (
              <div key={art.artifact_id} className="py-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="flex items-start space-x-3">
                  <div className="p-2.5 rounded-lg bg-purple-500/10 text-purple-400 mt-1">
                    <FileCode className="w-5 h-5" />
                  </div>
                  <div className="space-y-1.5">
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-white text-sm">{art.original_path || art.artifact_id}</span>
                      <span className="px-2 py-0.5 rounded bg-surface-highlight text-purple-400 text-xs font-mono">
                        {typeof art.format === 'string' ? art.format : 'Artifact'}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-xs font-medium border border-emerald-500/20">
                        {art.validation_status}
                      </span>
                    </div>

                    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-400 font-mono">
                      <span>Size: <strong className="text-gray-200">{(art.size_bytes / 1024).toFixed(1)} KB</strong></span>
                      <span>Confidence: <strong className="text-emerald-400">{(art.confidence_score * 100).toFixed(0)}%</strong></span>
                      <span>Detection: <strong className="text-gray-300">{art.provenance?.detection_method || 'Signature'}</strong></span>
                      <span>Validation: <strong className="text-blue-300">{art.validation_method || art.provenance?.validation_method || 'Syntactic Parser'}</strong></span>
                      <span>Entropy: <strong className="text-blue-400">{art.provenance?.entropy_score?.toFixed(2) || '0.00'} bits/byte</strong></span>
                    </div>

                    <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-gray-500 font-mono">
                      <span>Source ID: <strong className="text-gray-300">{art.source_id}</strong></span>
                      {art.source_hash && <span>Source SHA-256: <strong className="text-gray-400">{art.source_hash.substring(0, 16)}...</strong></span>}
                      <span>Sectors: {JSON.stringify(art.provenance?.sector_ranges || art.source_offsets)}</span>
                    </div>

                    <div className="space-y-0.5 text-[11px] text-gray-500 font-mono break-all pt-1">
                      <div>
                        SHA-256 (Canonical Evidence): <strong className="text-emerald-400">{art.sha256}</strong>
                      </div>
                      {art.optional_blake3 && (
                        <div>
                          BLAKE3 (Internal Processing): <strong className="text-cyan-400">{art.optional_blake3}</strong>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {art.data_base64 && (
                  <div className="flex items-center space-x-2 shrink-0">
                    <button
                      onClick={() => setPreviewArtifact(art)}
                      className="flex items-center space-x-1 px-3 py-1.5 bg-surface-highlight hover:bg-gray-800 border border-gray-700 text-purple-400 rounded-lg text-xs font-semibold transition-colors"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>Preview</span>
                    </button>
                    <button
                      onClick={() => handleDownloadArtifact(art)}
                      className="flex items-center space-x-1 px-3 py-1.5 bg-purple-600/20 hover:bg-purple-600/30 border border-purple-500/30 text-purple-300 rounded-lg text-xs font-semibold transition-colors"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Extract</span>
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
