import React, { useState, useEffect } from 'react';
import { Device, SanitizationStandard, SanitizationPlan } from '../types';
import { fetchDevices, fetchRecommendedPlan } from '../services/api';
import { Trash2, AlertOctagon, CheckCircle2 } from 'lucide-react';

export const Sanitization: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [standard, setStandard] = useState<SanitizationStandard>('Nist80088Purge');
  const [plan, setPlan] = useState<SanitizationPlan | null>(null);
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [completed, setCompleted] = useState<boolean>(false);

  useEffect(() => {
    fetchDevices().then((devs) => {
      setDevices(devs);
      const firstTarget = devs.find((d) => !d.system_disk && !d.boot_device) || devs[0];
      setSelectedDevice(firstTarget || null);
    });
  }, []);

  useEffect(() => {
    if (selectedDevice) {
      fetchRecommendedPlan(selectedDevice, standard).then(setPlan);
    }
  }, [selectedDevice, standard]);

  const handleStartSanitization = () => {
    if (!selectedDevice || selectedDevice.system_disk) return;
    setIsExecuting(true);
    setProgress(0);
    setCompleted(false);

    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          setIsExecuting(false);
          setCompleted(true);
          return 100;
        }
        return prev + 10;
      });
    }, 400);
  };

  return (
    <div className="p-8 space-y-6">
      <div>
        <h3 className="text-xl font-bold text-white">Sanitization Engine</h3>
        <p className="text-xs text-gray-400">Capability-aware storage destruction and compliance execution</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Configuration */}
        <div className="space-y-4">
          <div className="p-5 rounded-xl bg-surface border border-gray-800 space-y-4">
            <h4 className="text-sm font-semibold text-white">1. Select Target Media</h4>
            <div className="space-y-2">
              {devices.map((d) => {
                const isTarget = selectedDevice?.stable_id === d.stable_id;
                const isSystem = d.system_disk || d.boot_device;
                return (
                  <button
                    key={d.stable_id}
                    disabled={isExecuting}
                    onClick={() => setSelectedDevice(d)}
                    className={`w-full text-left p-3 rounded-lg border text-xs transition-all ${
                      isTarget
                        ? 'border-blue-500 bg-blue-600/10'
                        : isSystem
                        ? 'border-red-900/30 bg-surface opacity-75'
                        : 'border-gray-800 bg-surface-highlight/40 hover:border-gray-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-gray-200">{d.model}</span>
                      {isSystem && <span className="text-[10px] text-red-400 font-bold">SYSTEM</span>}
                    </div>
                    <div className="text-gray-400 font-mono mt-1">{d.path} • {d.serial}</div>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="p-5 rounded-xl bg-surface border border-gray-800 space-y-4">
            <h4 className="text-sm font-semibold text-white">2. Compliance Standard</h4>
            <select
              value={standard}
              disabled={isExecuting}
              onChange={(e) => setStandard(e.target.value as SanitizationStandard)}
              className="w-full bg-surface-highlight border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-blue-500"
            >
              <option value="Nist80088Purge">NIST SP 800-88 Rev 1 — Purge (Hardware Erase)</option>
              <option value="Nist80088Clear">NIST SP 800-88 Rev 1 — Clear (Logical Overwrite)</option>
              <option value="Dod522022M3Pass">DoD 5220.22-M (3-Pass Multi-Pattern)</option>
              <option value="Ieee2883Purge">IEEE 2883-2022 — Purge</option>
              <option value="SinglePassZero">Single-Pass Zero Stream (0x00)</option>
            </select>
          </div>
        </div>

        {/* Right Column: Plan & Execution */}
        <div className="lg:col-span-2 space-y-4">
          {plan && (
            <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-5">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs text-blue-400 font-mono font-semibold">PLAN ID: {plan.plan_id}</span>
                  <h4 className="text-lg font-bold text-white mt-1">Recommended Sanitization Procedure</h4>
                </div>
                <div className="px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-mono">
                  {typeof plan.method === 'string' ? plan.method : 'Custom Method'}
                </div>
              </div>

              <div className="p-4 rounded-lg bg-surface-highlight/50 border border-gray-800 text-xs space-y-2">
                <p className="text-gray-300 leading-relaxed font-sans">{plan.rationale}</p>
              </div>

              {plan.warnings.length > 0 && (
                <div className="p-4 rounded-lg bg-amber-950/30 border border-amber-500/30 text-xs text-amber-200/90 space-y-1">
                  <div className="font-semibold text-amber-300">Technical Warnings:</div>
                  {plan.warnings.map((w, i) => (
                    <div key={i}>• {w}</div>
                  ))}
                </div>
              )}

              {selectedDevice?.system_disk && (
                <div className="p-4 rounded-lg bg-red-950/40 border border-red-500/40 text-xs text-red-200 flex items-center space-x-3">
                  <AlertOctagon className="w-5 h-5 text-red-400 flex-shrink-0" />
                  <div>
                    <strong className="text-red-400">INVARIANT SAFETY GATE ACTIVE:</strong> System disk destruction is prohibited by policy.
                  </div>
                </div>
              )}

              {/* Execution Progress */}
              {isExecuting && (
                <div className="space-y-2 pt-2">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-gray-400">Executing Sanitization Routine...</span>
                    <span className="text-blue-400 font-bold">{progress}%</span>
                  </div>
                  <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
                    <div
                      className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${progress}%` }}
                    />
                  </div>
                </div>
              )}

              {completed && (
                <div className="p-4 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-xs text-emerald-300 flex items-center space-x-3">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
                  <div>
                    <strong>Sanitization Operation Complete.</strong> Proceed to L1–L4 Multi-Level Verification.
                  </div>
                </div>
              )}

              {/* Action Button */}
              <div className="pt-4 border-t border-gray-800 flex justify-end">
                <button
                  disabled={isExecuting || selectedDevice?.system_disk}
                  onClick={handleStartSanitization}
                  className={`inline-flex items-center space-x-2 px-5 py-2.5 rounded-lg text-sm font-semibold transition-all shadow-lg ${
                    selectedDevice?.system_disk
                      ? 'bg-gray-800 text-gray-500 cursor-not-allowed'
                      : 'bg-red-600 hover:bg-red-500 text-white shadow-red-600/20'
                  }`}
                >
                  <Trash2 className="w-4 h-4" />
                  <span>{isExecuting ? 'Sanitizing Target...' : 'Arm & Execute Plan'}</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
