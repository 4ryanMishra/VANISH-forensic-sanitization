import React, { useState } from 'react';
import { FileCode, Play, Download, ShieldCheck, CheckCircle2 } from 'lucide-react';
import { RecoveredArtifact, RecoveryJob } from '../types';
import { executeRecoveryJob } from '../services/api';

export const ForensicRecovery: React.FC = () => {
  const [selectedTarget, setSelectedTarget] = useState<string>('test-data/virtual-disks/vanish_lab_image.img');
  const [scanning, setScanning] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [artifacts, setArtifacts] = useState<RecoveredArtifact[]>([]);
  const [scanSummary, setScanSummary] = useState<{ scannedBytes: number; durationMs: number; isSim: boolean } | null>(null);

  const isSimulation = selectedTarget === 'disk-vdisk-01';

  const handleStartScan = async () => {
    setScanning(true);
    setProgress(0);
    setArtifacts([]);
    setScanSummary(null);

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
      });
    } catch (err) {
      console.error('Forensic recovery failed:', err);
      clearInterval(interval);
    } finally {
      setScanning(false);
    }
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
            <option value="test-data/virtual-disks/vanish_lab_image.img">
              Target 1: vanish_lab_image.img (16MB Raw Image)
            </option>
            <option value="disk-vdisk-01">
              Target 2: disk-vdisk-01 (In-Memory Virtual Disk)
            </option>
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
          <span className="font-semibold">Write-Block Status: Hardware/Kernel Read-Only Active</span>
        </div>
        <div className="text-gray-400">
          Mode: <strong className={isSimulation ? 'text-blue-400' : 'text-purple-400'}>{isSimulation ? 'SIMULATION MODE' : 'RAW DISK STREAM'}</strong>
        </div>
      </div>

      {/* Progress Bar */}
      {scanning && (
        <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-2">
          <div className="flex justify-between text-xs font-mono">
            <span className="text-gray-400">Scanning raw sector stream and filesystem slack...</span>
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
            <span>Bytes Scanned: <strong className="text-gray-200">{(scanSummary.scannedBytes / 1024).toFixed(1)} KB</strong></span>
            <span>Duration: <strong className="text-gray-200">{scanSummary.durationMs} ms</strong></span>
            <span>Mode: <strong className={scanSummary.isSim ? 'text-blue-400' : 'text-purple-400'}>{scanSummary.isSim ? 'SIMULATION' : 'RAW IMAGE'}</strong></span>
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
          <div className="p-8 text-center text-gray-500 text-sm">
            No active recovery session. Select a forensic target image and click "Start Carving Scan".
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
                      <span>Method: <strong className="text-gray-300">{art.provenance.detection_method}</strong></span>
                      <span>Entropy: <strong className="text-blue-400">{art.provenance.entropy_score.toFixed(2)} bits/byte</strong></span>
                      <span>Magic: <strong className="text-gray-300">{art.provenance.header_magic}</strong></span>
                    </div>

                    <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-gray-500 font-mono">
                      <span>Sector Ranges: {JSON.stringify(art.provenance.sector_ranges)}</span>
                      <span>Extracted: {art.extracted_path || 'In-Memory Stream'}</span>
                    </div>

                    <div className="text-[11px] text-gray-500 font-mono break-all">
                      SHA-256 (Canonical Evidence): <strong className="text-gray-400">{art.sha256}</strong>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
