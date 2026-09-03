import React from 'react';
import { Download, ShieldCheck } from 'lucide-react';
import { HashingIntegrity } from '../components/HashingIntegrity';

export const Reports: React.FC = () => {

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xl font-bold text-white">Attestation Certificates & Reports</h3>
          <p className="text-xs text-gray-400">Cryptographically signed sanitization compliance artifacts</p>
        </div>
      </div>

      <div className="p-8 rounded-xl bg-surface border border-gray-800 max-w-3xl space-y-6">
        <div className="flex items-center justify-between border-b border-gray-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className="p-3 rounded-lg bg-emerald-500/10 text-emerald-400">
              <ShieldCheck className="w-8 h-8" />
            </div>
            <div>
              <h4 className="text-lg font-bold text-white">Certificate of Forensic Sanitization</h4>
              <p className="text-xs text-gray-400 font-mono">CERT-VN-2026-0819-01</p>
            </div>
          </div>
          <button className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow-lg shadow-blue-600/20">
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON / PDF</span>
          </button>
        </div>

        <div className="grid grid-cols-2 gap-4 text-xs font-mono">
          <div>
            <span className="text-gray-500 block">TARGET DEVICE:</span>
            <span className="text-gray-200">SanDisk Ultra USB 3.0 (16 GB)</span>
          </div>
          <div>
            <span className="text-gray-500 block">SERIAL NUMBER:</span>
            <span className="text-gray-200">4C530001230415116032</span>
          </div>
          <div>
            <span className="text-gray-500 block">STANDARD APPLIED:</span>
            <span className="text-blue-400">NIST SP 800-88 Rev 1 (Clear)</span>
          </div>
          <div>
            <span className="text-gray-500 block">VERIFICATION LEVEL:</span>
            <span className="text-emerald-400">L1, L2, L4 Verified</span>
          </div>
        </div>

        <div className="p-4 rounded-lg bg-surface-highlight text-xs space-y-2">
          <span className="text-gray-400 font-bold block">VERIFICATION STATEMENT:</span>
          <p className="text-gray-300 italic">
            "No target artifact was recovered by the specified VANISH validation procedure."
          </p>
        </div>

        <div className="pt-4 border-t border-gray-800 flex items-center justify-between text-xs font-mono text-gray-500">
          <span>Digital Signature: Ed25519 Verified</span>
          <span>Tip Hash: 7b3f...91a2</span>
        </div>
      </div>

      <HashingIntegrity />
    </div>
  );
};

