import React, { useState, useEffect } from 'react';
import { 
  FileCode, 
  Play, 
  Download, 
  ShieldCheck, 
  CheckCircle2, 
  HardDrive, 
  Image as ImageIcon, 
  Eye, 
  Binary, 
  Search
} from 'lucide-react';
import { Device, RecoveredArtifact, RecoveryJob } from '../types';
import { executeRecoveryJob, fetchDevices } from '../services/api';
import { HexInspector } from '../components/HexInspector';
import { SectorClusterMap } from '../components/SectorClusterMap';

export const ForensicRecovery: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedTarget, setSelectedTarget] = useState<string>('test-data/virtual-disks/vanish_lab_image.img');
  const [scanning, setScanning] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [artifacts, setArtifacts] = useState<RecoveredArtifact[]>([]);
  const [scanSummary, setScanSummary] = useState<{ scannedBytes: number; durationMs: number; isSim: boolean; targetLabel?: string } | null>(null);
  const [previewArtifact, setPreviewArtifact] = useState<RecoveredArtifact | null>(null);
  const [hexInspectorArtifact, setHexInspectorArtifact] = useState<RecoveredArtifact | null>(null);

  useEffect(() => {
    fetchDevices().then((devs) => {
      setDevices(devs);
      const realTarget = devs.find((d) => !d.system_disk && !d.boot_device && !d.is_simulated);
      if (realTarget) {
        setSelectedTarget(realTarget.path);
      }
    });
  }, []);

  const isSimulation = selectedTarget === 'disk-vdisk-01';
  const isPhysical = selectedTarget.toUpperCase().includes('PHYSICALDRIVE') || selectedTarget.startsWith('\\\\.\\') || selectedTarget.startsWith('/dev/');
  const selectedDeviceObj = devices.find((d) => d.path === selectedTarget);

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
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header and Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-[10px] font-mono font-bold tracking-widest text-forensic uppercase bg-forensic/10 px-2 py-0.5 rounded border border-forensic/20">
              FORENSIC CARVING ENGINE
            </span>
            {isSimulation ? (
              <span className="px-2 py-0.5 rounded bg-amber/10 border border-amber/20 text-amber text-[10px] font-mono font-bold">
                SYNTHETIC BENCHMARK
              </span>
            ) : isPhysical ? (
              <span className="px-2 py-0.5 rounded bg-verified/10 border border-verified/20 text-verified text-[10px] font-mono font-bold flex items-center space-x-1">
                <HardDrive className="w-3 h-3" />
                <span>PHYSICAL DISK STREAM (READ-ONLY)</span>
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded bg-surface-elevated border border-border text-charcoal/70 text-[10px] font-mono font-bold">
                RAW IMAGE CARVING
              </span>
            )}
          </div>
          <h2 className="text-xl font-bold text-charcoal tracking-tight mt-1">
            Read-Only Forensic Acquisition & Deep Carving
          </h2>
          <p className="text-xs text-charcoal/60 mt-0.5">
            Non-destructive sector streaming, container parsing, fragmented reconstruction, and SHA-256 evidence provenance
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <select
            value={selectedTarget}
            onChange={(e) => setSelectedTarget(e.target.value)}
            disabled={scanning}
            className="bg-white border border-border text-charcoal text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-forensic font-mono shadow-subtle"
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
            className="flex items-center space-x-2 px-4 py-2 bg-forensic hover:bg-forensic-dark disabled:opacity-50 text-white rounded-lg text-xs font-semibold shadow-subtle transition-all"
          >
            <Play className={`w-3.5 h-3.5 ${scanning ? 'animate-pulse' : ''}`} />
            <span>{scanning ? 'Acquiring...' : 'Start Carving Scan'}</span>
          </button>
        </div>
      </div>

      {/* Write-Block Safety Callout */}
      <div className="p-4 rounded-xl bg-white border border-border flex items-center justify-between text-xs font-mono shadow-subtle">
        <div className="flex items-center space-x-2 text-verified">
          <ShieldCheck className="w-4 h-4" />
          <span className="font-semibold text-charcoal">Write-Block Status: Kernel Read-Only Active (Zero-Write Enforcement)</span>
        </div>
        <div className="text-charcoal/60">
          Mode: <strong className="text-forensic font-bold">{isSimulation ? 'SIMULATION MODE' : isPhysical ? 'PHYSICAL DEVICE RAW STREAM' : 'RAW IMAGE STREAM'}</strong>
        </div>
      </div>

      {/* Progress Bar */}
      {scanning && (
        <div className="p-5 rounded-xl bg-white border border-border space-y-2 shadow-subtle">
          <div className="flex justify-between text-xs font-mono">
            <span className="text-charcoal/70">Streaming raw physical sectors and analyzing container magic headers...</span>
            <span className="text-forensic font-bold">{progress}%</span>
          </div>
          <div className="w-full bg-surface-elevated rounded-full h-2 overflow-hidden">
            <div
              className="bg-forensic h-2 rounded-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Scan Summary Banner */}
      {scanSummary && !scanning && (
        <div className="p-4 rounded-xl bg-forensic/5 border border-forensic/20 flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
          <div className="flex items-center space-x-2 text-forensic font-bold">
            <CheckCircle2 className="w-4 h-4 text-forensic" />
            <span>Scan Complete: {artifacts.length} Artifacts Recovered & Validated</span>
          </div>
          <div className="flex items-center space-x-4 text-charcoal/70">
            <span>Bytes Scanned: <strong className="text-charcoal">{scanSummary.scannedBytes >= 1024 * 1024 ? `${(scanSummary.scannedBytes / (1024 * 1024)).toFixed(2)} MB` : `${(scanSummary.scannedBytes / 1024).toFixed(1)} KB`}</strong></span>
            <span>Duration: <strong className="text-charcoal">{scanSummary.durationMs} ms</strong></span>
            <span>Source: <strong className="text-forensic">{scanSummary.targetLabel || selectedTarget}</strong></span>
          </div>
        </div>
      )}

      {/* Sector Cluster Map */}
      <SectorClusterMap
        totalCapacityBytes={selectedDeviceObj ? selectedDeviceObj.capacity_bytes : 16 * 1024 * 1024 * 1024}
        activeScopeBytes={256 * 1024 * 1024}
        scannedBytes={scanSummary ? scanSummary.scannedBytes : 0}
        artifactsCount={artifacts.length}
      />

      {/* Image Preview Modal */}
      {previewArtifact && previewArtifact.data_base64 && (
        <div className="p-6 rounded-xl bg-white border border-forensic/30 space-y-3 shadow-subtle">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2 text-forensic">
              <ImageIcon className="w-4 h-4" />
              <span className="font-bold text-sm text-charcoal">
                Carved File Preview: {previewArtifact.original_path || previewArtifact.artifact_id}
              </span>
            </div>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => handleDownloadArtifact(previewArtifact)}
                className="flex items-center space-x-1 px-3 py-1 bg-forensic hover:bg-forensic-dark text-white rounded text-xs font-semibold shadow-subtle"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Save File</span>
              </button>
              <button
                onClick={() => setPreviewArtifact(null)}
                className="px-2.5 py-1 text-charcoal/60 hover:text-charcoal text-xs font-semibold rounded bg-surface-elevated hover:bg-border"
              >
                Close
              </button>
            </div>
          </div>
          <div className="flex justify-center p-6 bg-surface-elevated rounded-lg border border-border">
            {typeof previewArtifact.format === 'string' && (previewArtifact.format.toLowerCase() === 'jpeg' || previewArtifact.format.toLowerCase() === 'png' || previewArtifact.format.toLowerCase() === 'gif') ? (
              <img
                src={`data:image/${previewArtifact.format.toLowerCase() === 'jpeg' ? 'jpeg' : previewArtifact.format.toLowerCase()};base64,${previewArtifact.data_base64}`}
                alt="Carved Artifact"
                className="max-h-72 max-w-full rounded shadow object-contain border border-border bg-white"
              />
            ) : (
              <div className="p-8 text-xs font-mono text-charcoal/60 text-center">
                Binary preview: {previewArtifact.size_bytes} bytes reconstructed. Click "Save File" to export.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Recovered Artifacts Table */}
      <div className="p-6 rounded-xl bg-white border border-border space-y-4 shadow-subtle">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="text-sm font-bold text-charcoal uppercase tracking-wider">
              Recovered Evidence Artifacts ({artifacts.length})
            </h4>
            <p className="text-xs text-charcoal/50 font-sans mt-0.5">
              Strict cryptographic provenance with SHA-256 canonical fingerprints and syntactic parser validations
            </p>
          </div>
          {artifacts.length > 0 && (
            <button
              onClick={handleExportManifest}
              className="flex items-center space-x-1.5 px-3 py-1.5 bg-surface-elevated hover:bg-border border border-border text-charcoal rounded-lg text-xs font-semibold transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-telemetry" />
              <span>Export Carved Manifest</span>
            </button>
          )}
        </div>

        {artifacts.length === 0 && !scanning && (
          <div className="p-12 text-center text-charcoal/40 text-xs font-mono space-y-2 border border-dashed border-border rounded-lg">
            <Search className="w-8 h-8 mx-auto opacity-30 text-charcoal" />
            <p>No active recovery session. Select target storage endpoint and click "Start Carving Scan".</p>
          </div>
        )}

        {artifacts.length > 0 && (
          <div className="divide-y divide-border">
            {artifacts.map((art) => (
              <div key={art.artifact_id} className="py-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div className="flex items-start space-x-3.5">
                  <div className="p-2.5 rounded-lg bg-forensic/10 text-forensic border border-forensic/20 mt-1 shrink-0">
                    <FileCode className="w-5 h-5" />
                  </div>
                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-bold text-charcoal text-sm">{art.original_path || art.artifact_id}</span>
                      <span className="px-2 py-0.5 rounded bg-surface-elevated text-forensic text-xs font-mono font-bold border border-border">
                        {typeof art.format === 'string' ? art.format : 'Artifact'}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-verified/10 text-verified text-xs font-bold border border-verified/20 font-mono">
                        {art.validation_status}
                      </span>
                    </div>

                    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-charcoal/60 font-mono">
                      <span>Size: <strong className="text-charcoal font-semibold">{(art.size_bytes / 1024).toFixed(1)} KB</strong></span>
                      <span>Confidence: <strong className="text-verified font-semibold">{(art.confidence_score * 100).toFixed(0)}%</strong></span>
                      <span>Detection: <strong className="text-charcoal font-semibold">{art.provenance?.detection_method || 'Signature'}</strong></span>
                      <span>Validation: <strong className="text-telemetry font-semibold">{art.validation_method || art.provenance?.validation_method || 'Syntactic Parser'}</strong></span>
                      <span>Entropy: <strong className="text-forensic font-semibold">{art.provenance?.entropy_score?.toFixed(2) || '0.00'} bits/byte</strong></span>
                    </div>

                    <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-charcoal/50 font-mono">
                      <span>Source ID: <strong className="text-charcoal/70">{art.source_id}</strong></span>
                      {art.source_hash && <span>Source SHA-256: <strong className="text-charcoal/70">{art.source_hash.substring(0, 16)}...</strong></span>}
                      <span>Sectors: {JSON.stringify(art.provenance?.sector_ranges || art.source_offsets)}</span>
                    </div>

                    <div className="space-y-0.5 text-[11px] text-charcoal/60 font-mono break-all pt-1">
                      <div>
                        SHA-256 (Canonical Evidence): <strong className="text-verified font-semibold">{art.sha256}</strong>
                      </div>
                      {art.optional_blake3 && (
                        <div>
                          BLAKE3 (Internal Processing): <strong className="text-telemetry font-semibold">{art.optional_blake3}</strong>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-2 shrink-0 border-t lg:border-t-0 pt-2 lg:pt-0 border-border">
                  <button
                    onClick={() => setHexInspectorArtifact(art)}
                    className="flex items-center space-x-1 px-3 py-1.5 bg-surface-elevated hover:bg-border border border-border text-charcoal rounded-lg text-xs font-semibold transition-colors"
                  >
                    <Binary className="w-3.5 h-3.5 text-telemetry" />
                    <span>Hex Inspector</span>
                  </button>
                  {art.data_base64 && (
                    <>
                      <button
                        onClick={() => setPreviewArtifact(art)}
                        className="flex items-center space-x-1 px-3 py-1.5 bg-forensic/10 hover:bg-forensic/20 border border-forensic/30 text-forensic rounded-lg text-xs font-semibold transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span>Preview</span>
                      </button>
                      <button
                        onClick={() => handleDownloadArtifact(art)}
                        className="flex items-center space-x-1 px-3 py-1.5 bg-forensic hover:bg-forensic-dark text-white rounded-lg text-xs font-semibold shadow-subtle transition-colors"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>Extract</span>
                      </button>
                    </>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Hex Inspector Drawer */}
      <HexInspector
        artifact={hexInspectorArtifact}
        onClose={() => setHexInspectorArtifact(null)}
      />
    </div>
  );
};
