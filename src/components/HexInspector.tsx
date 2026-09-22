import React, { useState } from 'react';
import { Binary, Copy, Check, X, Download } from 'lucide-react';
import { RecoveredArtifact } from '../types';

interface HexInspectorProps {
  artifact: RecoveredArtifact | null;
  onClose: () => void;
}

export const HexInspector: React.FC<HexInspectorProps> = ({ artifact, onClose }) => {
  const [copied, setCopied] = useState(false);
  const [page, setPage] = useState(0);
  const BYTES_PER_PAGE = 512; // 32 lines of 16 bytes

  if (!artifact) return null;

  let rawBytes: Uint8Array | null = null;
  if (artifact.data_base64) {
    try {
      const binaryString = atob(artifact.data_base64);
      const len = binaryString.length;
      rawBytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        rawBytes[i] = binaryString.charCodeAt(i);
      }
    } catch {
      rawBytes = null;
    }
  }

  const totalPages = rawBytes ? Math.ceil(rawBytes.length / BYTES_PER_PAGE) : 1;
  const startByte = page * BYTES_PER_PAGE;
  const pageSlice = rawBytes ? rawBytes.slice(startByte, startByte + BYTES_PER_PAGE) : null;

  // Render 16 bytes per line
  const lines: { offset: number; hexCol1: string[]; hexCol2: string[]; ascii: string }[] = [];
  if (pageSlice) {
    for (let i = 0; i < pageSlice.length; i += 16) {
      const chunk = pageSlice.slice(i, i + 16);
      const col1: string[] = [];
      const col2: string[] = [];
      let ascii = '';

      for (let j = 0; j < 16; j++) {
        if (j < chunk.length) {
          const byte = chunk[j];
          const hex = byte.toString(16).padStart(2, '0').toUpperCase();
          if (j < 8) col1.push(hex);
          else col2.push(hex);

          // Printable ASCII (32 to 126)
          if (byte >= 32 && byte <= 126) {
            ascii += String.fromCharCode(byte);
          } else {
            ascii += '·';
          }
        } else {
          if (j < 8) col1.push('  ');
          else col2.push('  ');
          ascii += ' ';
        }
      }

      lines.push({
        offset: startByte + i,
        hexCol1: col1,
        hexCol2: col2,
        ascii,
      });
    }
  }

  const handleCopyHex = () => {
    if (!pageSlice) return;
    const hexString = Array.from(pageSlice)
      .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
      .join(' ');
    navigator.clipboard.writeText(hexString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExportBinary = () => {
    if (!rawBytes) return;
    const blob = new Blob([rawBytes as BlobPart], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `VANISH_HEX_${artifact.artifact_id}.bin`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-y-0 right-0 w-full max-w-2xl bg-surface border-l border-border shadow-popover z-50 flex flex-col animate-in slide-in-from-right duration-200">
      {/* Header */}
      <div className="px-6 py-4 border-b border-border flex items-center justify-between bg-surface-subtle">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded bg-forensic-surface text-forensic border border-forensic-border">
            <Binary className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-charcoal flex items-center space-x-2">
              <span>Hex / Byte Inspector</span>
              <span className="text-xs font-mono text-charcoal-muted">[{artifact.artifact_id}]</span>
            </h3>
            <p className="text-xs text-charcoal-muted font-mono">
              Format: {typeof artifact.format === 'string' ? artifact.format : 'Binary'} · Size: {artifact.size_bytes.toLocaleString()} bytes · Entropy: {artifact.provenance?.entropy_score?.toFixed(2) || '0.00'} bits/B
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          {rawBytes && (
            <>
              <button
                onClick={handleCopyHex}
                title="Copy current page hex bytes"
                className="p-1.5 text-xs text-charcoal-secondary hover:text-charcoal bg-surface border border-border rounded hover:bg-surface-hover flex items-center space-x-1"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-verified" /> : <Copy className="w-3.5 h-3.5" />}
                <span className="text-[11px] font-mono">{copied ? 'Copied' : 'Copy'}</span>
              </button>
              <button
                onClick={handleExportBinary}
                title="Download raw reconstructed bytes"
                className="p-1.5 text-xs text-charcoal-secondary hover:text-charcoal bg-surface border border-border rounded hover:bg-surface-hover flex items-center space-x-1"
              >
                <Download className="w-3.5 h-3.5" />
                <span className="text-[11px] font-mono">Save</span>
              </button>
            </>
          )}
          <button
            onClick={onClose}
            className="p-1.5 text-charcoal-muted hover:text-charcoal hover:bg-surface-hover rounded"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Hex Content */}
      <div className="flex-1 overflow-y-auto p-6 font-mono text-xs select-text">
        {!rawBytes ? (
          <div className="h-full flex flex-col items-center justify-center text-center p-8 border border-dashed border-border rounded-lg bg-surface-subtle">
            <Binary className="w-8 h-8 text-charcoal-faint mb-2" />
            <h4 className="text-xs font-semibold uppercase tracking-wider text-charcoal">Raw Byte Stream Unavailable</h4>
            <p className="text-xs text-charcoal-muted max-w-sm mt-1">
              Byte representation was not retained in-memory for this artifact. Re-run forensic scan or export the full manifest.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {/* Hex Column Headers */}
            <div className="grid grid-cols-[80px_1fr_1fr_140px] text-[11px] font-semibold text-charcoal-muted pb-2 border-b border-border">
              <span>OFFSET</span>
              <span>00 01 02 03 04 05 06 07</span>
              <span>08 09 0A 0B 0C 0D 0E 0F</span>
              <span>ASCII DECODE</span>
            </div>

            {/* Hex Rows */}
            <div className="space-y-1">
              {lines.map((row) => (
                <div
                  key={row.offset}
                  className="grid grid-cols-[80px_1fr_1fr_140px] text-[11px] hover:bg-surface-hover px-1 py-0.5 rounded font-mono leading-relaxed"
                >
                  <span className="text-charcoal-muted select-none">
                    {row.offset.toString(16).padStart(8, '0').toUpperCase()}
                  </span>
                  <span className="text-charcoal font-mono tracking-wider">
                    {row.hexCol1.join(' ')}
                  </span>
                  <span className="text-charcoal font-mono tracking-wider">
                    {row.hexCol2.join(' ')}
                  </span>
                  <span className="text-forensic font-mono break-all tracking-normal">
                    {row.ascii}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Footer Pagination */}
      {rawBytes && totalPages > 1 && (
        <div className="px-6 py-3 border-t border-border bg-surface-subtle flex items-center justify-between text-xs font-mono">
          <span className="text-charcoal-muted">
            Offset {startByte.toString(16).toUpperCase()} - {Math.min(startByte + BYTES_PER_PAGE, rawBytes.length).toString(16).toUpperCase()} of {rawBytes.length.toString(16).toUpperCase()}h bytes
          </span>
          <div className="flex items-center space-x-2">
            <button
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              className="px-2 py-1 bg-surface border border-border rounded text-charcoal disabled:opacity-40 disabled:cursor-not-allowed hover:bg-surface-hover"
            >
              Prev
            </button>
            <span className="text-charcoal-secondary font-semibold">
              Page {page + 1} / {totalPages}
            </span>
            <button
              disabled={page >= totalPages - 1}
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              className="px-2 py-1 bg-surface border border-border rounded text-charcoal disabled:opacity-40 disabled:cursor-not-allowed hover:bg-surface-hover"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
