import React, { useState } from 'react';
import { FileCode, Play } from 'lucide-react';
import { RecoveredArtifact } from '../types';
import { scanAndRecoverArtifacts } from '../services/api';

export const ForensicRecovery: React.FC = () => {
  const [scanning, setScanning] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [artifacts, setArtifacts] = useState<RecoveredArtifact[]>([]);

  const handleStartScan = async () => {
    setScanning(true);
    setProgress(0);
    setArtifacts([]);

    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 90) {
          return 90;
        }
        return prev + 15;
      });
    }, 150);

    try {
      const recovered = await scanAndRecoverArtifacts('disk-vdisk-01', true);
      clearInterval(interval);
      setProgress(100);
      setArtifacts(recovered);
    } catch (err) {
      console.error('Forensic recovery failed:', err);
      clearInterval(interval);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xl font-bold text-white">Read-Only Forensic Analysis</h3>
          <p className="text-xs text-gray-400">Raw signature carving, fragmented reconstruction, and artifact validation</p>
        </div>
        <button
          onClick={handleStartScan}
          disabled={scanning}
          className="flex items-center space-x-2 px-4 py-2.5 bg-purple-600 hover:bg-purple-500 disabled:bg-gray-800 text-white rounded-lg text-sm font-semibold transition-colors shadow-lg shadow-purple-600/20"
        >
          <Play className="w-4 h-4" />
          <span>{scanning ? 'Scanning Evidence...' : 'Start Carving Scan'}</span>
        </button>
      </div>

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

      {/* Recovered Artifacts Table */}
      <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-4">
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-bold text-white uppercase tracking-wider">
            Recovered Evidence Artifacts ({artifacts.length})
          </h4>
          <span className="text-xs text-emerald-400 font-mono">All sources mounted in read-only write-blocked mode</span>
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
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-white text-sm">{art.original_path || art.artifact_id}</span>
                      <span className="px-2 py-0.5 rounded bg-surface-highlight text-purple-400 text-xs font-mono">
                        {typeof art.format === 'string' ? art.format : 'Artifact'}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-xs font-medium border border-emerald-500/20">
                        {art.validation_status}
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-400 mt-2 font-mono">
                      <span>Size: <strong className="text-gray-200">{(art.size_bytes / 1024).toFixed(1)} KB</strong></span>
                      <span>Confidence: <strong className="text-emerald-400">{(art.confidence_score * 100).toFixed(0)}%</strong></span>
                      <span>Method: <strong className="text-gray-300">{art.provenance.detection_method}</strong></span>
                      <span>Entropy: <strong className="text-blue-400">{art.provenance.entropy_score.toFixed(2)}</strong></span>
                    </div>
                    <div className="text-[11px] text-gray-500 font-mono mt-1">
                      SHA256: {art.sha256}
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
