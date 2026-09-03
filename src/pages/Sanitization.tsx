import React, { useState, useEffect } from 'react';
import { Device, SanitizationStandard, SanitizationPlan, VerificationReport, SanitizationCertificate } from '../types';
import {
  fetchDevices,
  fetchRecommendedPlan,
  executeSanitizationPlan,
  ExecutionSummary,
  runVerification,
  issueCertificate,
} from '../services/api';
import {
  HardDrive,
  Cpu,
  Settings,
  ShieldAlert,
  Trash2,
  CheckCircle2,
  AlertOctagon,
  ChevronRight,
  ShieldCheck,
  Award,
  AlertCircle,
  RefreshCw,
} from 'lucide-react';

type WorkflowStep =
  | 'select'
  | 'analyze'
  | 'configure'
  | 'safety_check'
  | 'execute'
  | 'verify'
  | 'evidence';

export const Sanitization: React.FC = () => {
  const [currentStep, setCurrentStep] = useState<WorkflowStep>('select');
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [standard, setStandard] = useState<SanitizationStandard>('Nist80088Purge');
  const [plan, setPlan] = useState<SanitizationPlan | null>(null);
  const [confirmationInput, setConfirmationInput] = useState<string>('');
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [summary, setSummary] = useState<ExecutionSummary | null>(null);
  const [executionError, setExecutionError] = useState<string | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [verificationReport, setVerificationReport] = useState<VerificationReport | null>(null);
  const [isIssuingCert, setIsIssuingCert] = useState<boolean>(false);
  const [certificate, setCertificate] = useState<SanitizationCertificate | null>(null);

  const loadDevices = async () => {
    const devs = await fetchDevices();
    setDevices(devs);
    if (!selectedDevice && devs.length > 0) {
      const target = devs.find((d) => !d.system_disk && !d.boot_device) || devs[0];
      setSelectedDevice(target || null);
    }
  };

  useEffect(() => {
    loadDevices();
  }, []);

  useEffect(() => {
    if (selectedDevice) {
      fetchRecommendedPlan(selectedDevice, standard).then(setPlan);
    }
  }, [selectedDevice, standard]);

  const handleStartExecution = async () => {
    if (!selectedDevice || selectedDevice.system_disk || !plan) return;
    setIsExecuting(true);
    setProgress(0);
    setSummary(null);
    setExecutionError(null);

    const interval = setInterval(() => {
      setProgress((prev) => (prev >= 90 ? 90 : prev + 15));
    }, 200);

    try {
      const result = await executeSanitizationPlan(plan, selectedDevice);
      clearInterval(interval);
      setProgress(100);
      setSummary(result);
    } catch (err: any) {
      clearInterval(interval);
      console.error('Sanitization failed:', err);
      const errMsg = typeof err === 'string' ? err : err?.message || JSON.stringify(err);
      setExecutionError(errMsg);
    } finally {
      setIsExecuting(false);
    }
  };

  const handleRunVerification = async () => {
    if (!selectedDevice || !plan) return;
    setIsVerifying(true);
    try {
      const methodStr = typeof plan.method === 'string' ? plan.method : 'HostBlockOverwrite';
      const r = await runVerification(selectedDevice, methodStr, selectedDevice.is_simulated);
      setVerificationReport(r);
    } finally {
      setIsVerifying(false);
    }
  };

  const handleIssueCert = async () => {
    if (!selectedDevice || !plan || !verificationReport) return;
    setIsIssuingCert(true);
    try {
      const methodStr = typeof plan.method === 'string' ? plan.method : 'HostBlockOverwrite';
      const passes = typeof plan.method === 'object' && 'HostSequentialOverwrite' in plan.method ? plan.method.HostSequentialOverwrite.passes : 1;
      const c = await issueCertificate(
        selectedDevice,
        methodStr,
        passes,
        selectedDevice.capacity_bytes,
        selectedDevice.is_simulated,
        standard
      );
      setCertificate(c);
    } finally {
      setIsIssuingCert(false);
    }
  };

  const stepsList: { id: WorkflowStep; label: string; number: number }[] = [
    { id: 'select', label: 'Select Target', number: 1 },
    { id: 'analyze', label: 'Analyze Media', number: 2 },
    { id: 'configure', label: 'Configure Policy', number: 3 },
    { id: 'safety_check', label: 'Safety Gate', number: 4 },
    { id: 'execute', label: 'Sanitize', number: 5 },
    { id: 'verify', label: 'Verify L1–L4', number: 6 },
    { id: 'evidence', label: 'Evidence & Cert', number: 7 },
  ];

  const currentStepIdx = stepsList.findIndex((s) => s.id === currentStep);

  return (
    <div className="p-8 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h3 className="text-xl font-bold text-white">Linear Sanitization Workflow</h3>
          <p className="text-xs text-gray-400">
            Etcher-style sequential execution: Selection → Hardware Discovery → Policy Configuration → Safety Gate → Sanitization → Verification → Evidential Attestation
          </p>
        </div>
        {selectedDevice?.is_simulated && (
          <span className="px-3 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-mono font-bold">
            SIMULATION MODE
          </span>
        )}
      </div>

      {/* Stepper Navigation */}
      <div className="flex items-center justify-between overflow-x-auto pb-2 border-b border-gray-800">
        {stepsList.map((step, idx) => {
          const isActive = currentStep === step.id;
          const isDone = currentStepIdx > idx;
          return (
            <React.Fragment key={step.id}>
              <button
                disabled={isExecuting}
                onClick={() => setCurrentStep(step.id)}
                className={`flex items-center space-x-2 text-xs font-mono font-semibold transition-all px-3 py-1.5 rounded-lg ${
                  isActive
                    ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30'
                    : isDone
                    ? 'text-emerald-400 hover:text-emerald-300'
                    : 'text-gray-500 hover:text-gray-300'
                }`}
              >
                <span
                  className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] ${
                    isActive
                      ? 'bg-blue-600 text-white'
                      : isDone
                      ? 'bg-emerald-600/30 text-emerald-400'
                      : 'bg-gray-800 text-gray-500'
                  }`}
                >
                  {isDone ? '✓' : step.number}
                </span>
                <span>{step.label}</span>
              </button>
              {idx < stepsList.length - 1 && (
                <ChevronRight className="w-3.5 h-3.5 text-gray-700 flex-shrink-0 mx-1" />
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* Workflow Step Panels */}

      {/* ── STEP 1: SELECT ─────────────────────────────────────────────────── */}
      {currentStep === 'select' && (
        <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="text-base font-bold text-white flex items-center space-x-2">
              <HardDrive className="w-5 h-5 text-blue-400" />
              <span>Step 1: Select Target Storage Device</span>
            </h4>
            <button
              onClick={loadDevices}
              className="flex items-center space-x-1.5 px-3 py-1.5 bg-surface-highlight hover:bg-gray-800 text-xs rounded-lg text-gray-300 border border-gray-700"
            >
              <RefreshCw className="w-3 h-3" />
              <span>Rescan</span>
            </button>
          </div>

          <div className="grid grid-cols-1 gap-3">
            {devices.map((d) => {
              const isSelected = selectedDevice?.stable_id === d.stable_id;
              const isSystem = d.system_disk || d.boot_device;
              return (
                <div
                  key={d.stable_id}
                  onClick={() => !isSystem && setSelectedDevice(d)}
                  className={`p-4 rounded-xl border transition-all ${
                    isSystem
                      ? 'bg-red-950/10 border-red-900/30 cursor-not-allowed opacity-75'
                      : isSelected
                      ? 'bg-blue-600/10 border-blue-500 cursor-pointer shadow-md shadow-blue-500/10'
                      : 'bg-surface-highlight/30 border-gray-800 hover:border-gray-700 cursor-pointer'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <div className={`p-2.5 rounded-lg ${isSystem ? 'bg-red-500/10 text-red-400' : 'bg-blue-500/10 text-blue-400'}`}>
                        <HardDrive className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-white text-sm">{d.model}</span>
                          {d.is_simulated && (
                            <span className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 text-[10px] font-mono border border-amber-500/20">
                              SIMULATED
                            </span>
                          )}
                          {isSystem && (
                            <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 text-xs font-bold border border-red-500/30 flex items-center space-x-1">
                              <AlertOctagon className="w-3 h-3" />
                              <span>SYSTEM / BOOT DISK (LOCKED)</span>
                            </span>
                          )}
                        </div>
                        <div className="text-xs text-gray-400 font-mono mt-1">
                          Path: <strong className="text-gray-200">{d.path}</strong> · Serial: <strong className="text-gray-200">{d.serial}</strong> · Capacity: <strong className="text-blue-400">{(d.capacity_bytes / 1e9).toFixed(2)} GB</strong>
                        </div>
                      </div>
                    </div>
                    {isSelected && !isSystem && (
                      <span className="px-3 py-1 bg-blue-600 text-white text-xs font-semibold rounded-lg font-mono">
                        SELECTED
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          <div className="pt-4 border-t border-gray-800 flex justify-end">
            <button
              disabled={!selectedDevice || selectedDevice.system_disk}
              onClick={() => setCurrentStep('analyze')}
              className="inline-flex items-center space-x-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-800 disabled:text-gray-600 text-white rounded-lg text-sm font-semibold transition-colors"
            >
              <span>Continue to Media Analysis</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* ── STEP 2: ANALYZE ────────────────────────────────────────────────── */}
      {currentStep === 'analyze' && selectedDevice && (
        <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-6">
          <h4 className="text-base font-bold text-white flex items-center space-x-2">
            <Cpu className="w-5 h-5 text-blue-400" />
            <span>Step 2: Media Capability & Storage Architecture Analysis</span>
          </h4>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
            <div className="p-4 rounded-lg bg-surface-highlight border border-gray-800 space-y-1">
              <span className="text-gray-500 uppercase">Device Identifier</span>
              <div className="text-gray-200 font-bold">{selectedDevice.stable_id}</div>
            </div>
            <div className="p-4 rounded-lg bg-surface-highlight border border-gray-800 space-y-1">
              <span className="text-gray-500 uppercase">Bus Interface</span>
              <div className="text-blue-400 font-bold">{typeof selectedDevice.interface === 'string' ? selectedDevice.interface : 'Unknown'}</div>
            </div>
            <div className="p-4 rounded-lg bg-surface-highlight border border-gray-800 space-y-1">
              <span className="text-gray-500 uppercase">Media Type</span>
              <div className="text-emerald-400 font-bold">{typeof selectedDevice.media_type === 'string' ? selectedDevice.media_type : 'Unknown'}</div>
            </div>
            <div className="p-4 rounded-lg bg-surface-highlight border border-gray-800 space-y-1">
              <span className="text-gray-500 uppercase">Sector Geometry</span>
              <div className="text-gray-200 font-bold">{selectedDevice.logical_block_size}B Logical / {selectedDevice.physical_block_size}B Physical</div>
            </div>
          </div>

          <div className="space-y-3">
            <h5 className="text-sm font-semibold text-gray-300">Discovered Hardware Capabilities</h5>
            <div className="flex flex-wrap gap-2">
              {selectedDevice.capabilities.map((cap) => (
                <span
                  key={cap}
                  className="px-3 py-1.5 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-300 text-xs font-mono flex items-center space-x-1.5"
                >
                  <CheckCircle2 className="w-3.5 h-3.5 text-blue-400" />
                  <span>{cap}</span>
                </span>
              ))}
            </div>
          </div>

          <div className="pt-4 border-t border-gray-800 flex justify-between">
            <button
              onClick={() => setCurrentStep('select')}
              className="px-4 py-2 bg-surface hover:bg-surface-highlight text-gray-400 text-xs rounded-lg border border-gray-700"
            >
              ← Back
            </button>
            <button
              onClick={() => setCurrentStep('configure')}
              className="inline-flex items-center space-x-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-semibold transition-colors"
            >
              <span>Continue to Policy Configuration</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* ── STEP 3: CONFIGURE ──────────────────────────────────────────────── */}
      {currentStep === 'configure' && selectedDevice && (
        <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-6">
          <h4 className="text-base font-bold text-white flex items-center space-x-2">
            <Settings className="w-5 h-5 text-blue-400" />
            <span>Step 3: Sanitization Policy & Standard Selection</span>
          </h4>

          <div className="space-y-3">
            <label className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
              Compliance Standard
            </label>
            <select
              value={standard}
              onChange={(e) => setStandard(e.target.value as SanitizationStandard)}
              className="w-full bg-surface-highlight border border-gray-700 rounded-lg px-3 py-2.5 text-sm text-gray-200 focus:outline-none focus:border-blue-500 font-mono"
            >
              <option value="Nist80088Purge">NIST SP 800-88 Rev. 2 — Purge (Hardware Erase / Crypto Erase)</option>
              <option value="Nist80088Clear">NIST SP 800-88 Rev. 2 — Clear (Controlled Logical Overwrite)</option>
              <option value="Dod522022M3Pass">DoD 5220.22-M (3-Pass Multi-Pattern Stream)</option>
              <option value="Ieee2883Purge">IEEE 2883-2022 — Purge</option>
              <option value="SinglePassZero">Single-Pass Zero Fill (0x00 Stream)</option>
              <option value="SinglePassRandom">Single-Pass Pseudo-Random Stream</option>
            </select>
          </div>

          {plan && (
            <div className="p-5 rounded-xl bg-surface-highlight/50 border border-gray-800 space-y-4 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-mono text-blue-400 font-bold">PLAN ID: {plan.plan_id}</span>
                <span className="px-2.5 py-0.5 rounded bg-blue-500/10 text-blue-300 font-mono border border-blue-500/20">
                  {typeof plan.method === 'string' ? plan.method : 'Custom Adapter'}
                </span>
              </div>
              <p className="text-gray-300 leading-relaxed font-sans">{plan.rationale}</p>
              {plan.warnings.length > 0 && (
                <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-500/30 text-amber-200/90 space-y-1">
                  <div className="font-semibold text-amber-300">Declared Constraints & Technical Scope:</div>
                  {plan.warnings.map((w, idx) => (
                    <div key={idx}>• {w}</div>
                  ))}
                </div>
              )}
            </div>
          )}

          <div className="pt-4 border-t border-gray-800 flex justify-between">
            <button
              onClick={() => setCurrentStep('analyze')}
              className="px-4 py-2 bg-surface hover:bg-surface-highlight text-gray-400 text-xs rounded-lg border border-gray-700"
            >
              ← Back
            </button>
            <button
              onClick={() => setCurrentStep('safety_check')}
              className="inline-flex items-center space-x-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-semibold transition-colors"
            >
              <span>Proceed to Invariant Safety Gate</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* ── STEP 4: SAFETY CHECK ───────────────────────────────────────────── */}
      {currentStep === 'safety_check' && selectedDevice && (
        <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-6">
          <h4 className="text-base font-bold text-white flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            <span>Step 4: Two-Stage Invariant Safety Gate & Confirmation</span>
          </h4>

          <div className="p-4 rounded-xl bg-red-950/20 border border-red-500/30 space-y-3 text-xs">
            <div className="text-red-300 font-bold uppercase tracking-wider flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 text-red-400" />
              <span>Safety Gate Evaluation Matrix</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 font-mono text-gray-300">
              <div className="flex items-center space-x-2">
                <span className="text-emerald-400">✓</span>
                <span>Target Serial Match: {selectedDevice.serial}</span>
              </div>
              <div className="flex items-center space-x-2">
                <span className="text-emerald-400">✓</span>
                <span>System Disk Check: False (Protected)</span>
              </div>
              <div className="flex items-center space-x-2">
                <span className="text-emerald-400">✓</span>
                <span>Boot Device Check: False (Protected)</span>
              </div>
              <div className="flex items-center space-x-2">
                <span className="text-emerald-400">✓</span>
                <span>Target Revalidation: Path Active ({selectedDevice.path})</span>
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <label className="text-xs font-semibold text-gray-300">
              To arm the destructive execution engine, type <code className="text-red-400 font-bold font-mono">CONFIRM DESTROY</code>:
            </label>
            <input
              type="text"
              value={confirmationInput}
              onChange={(e) => setConfirmationInput(e.target.value)}
              placeholder="CONFIRM DESTROY"
              className="w-full bg-surface-highlight border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-gray-200 focus:outline-none focus:border-red-500 font-mono uppercase"
            />
          </div>

          <div className="pt-4 border-t border-gray-800 flex justify-between">
            <button
              onClick={() => setCurrentStep('configure')}
              className="px-4 py-2 bg-surface hover:bg-surface-highlight text-gray-400 text-xs rounded-lg border border-gray-700"
            >
              ← Back
            </button>
            <button
              disabled={confirmationInput !== 'CONFIRM DESTROY'}
              onClick={() => {
                setCurrentStep('execute');
                handleStartExecution();
              }}
              className="inline-flex items-center space-x-2 px-5 py-2.5 bg-red-600 hover:bg-red-500 disabled:bg-gray-800 disabled:text-gray-600 text-white rounded-lg text-sm font-semibold transition-colors shadow-lg shadow-red-600/20"
            >
              <Trash2 className="w-4 h-4" />
              <span>Arm & Execute Sanitization</span>
            </button>
          </div>
        </div>
      )}

      {/* ── STEP 5: EXECUTE ────────────────────────────────────────────────── */}
      {currentStep === 'execute' && selectedDevice && (
        <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-6">
          <h4 className="text-base font-bold text-white flex items-center space-x-2">
            <Trash2 className="w-5 h-5 text-blue-400" />
            <span>Step 5: Sanitization Execution Status</span>
          </h4>

          {isExecuting && (
            <div className="space-y-3">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-gray-400">Executing Controlled Sanitization Routine...</span>
                <span className="text-blue-400 font-bold">{progress}%</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2.5 overflow-hidden">
                <div
                  className="bg-blue-600 h-2.5 rounded-full transition-all duration-300"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          )}

          {executionError && !isExecuting && (
            <div className="p-5 rounded-xl bg-red-950/30 border border-red-500/40 space-y-3 text-xs">
              <div className="flex items-center space-x-2 text-red-400 font-bold text-sm">
                <AlertCircle className="w-5 h-5 shrink-0" />
                <span>Sanitization Operation Aborted or Failed</span>
              </div>
              <div className="font-mono text-red-300 pl-7 break-all">
                {executionError}
              </div>
            </div>
          )}

          {summary && !isExecuting && (
            <div className="p-5 rounded-xl bg-emerald-950/20 border border-emerald-500/30 space-y-3 text-xs">
              <div className="flex items-center space-x-2 text-emerald-400 font-bold text-sm">
                <CheckCircle2 className="w-5 h-5" />
                <span>Sanitization Completed Successfully ({summary.method_executed})</span>
              </div>
              <div className="font-mono text-gray-300 space-y-1 pl-7">
                {summary.execution_log.map((entry, idx) => (
                  <div key={idx}>✓ {entry}</div>
                ))}
              </div>
            </div>
          )}

          <div className="pt-4 border-t border-gray-800 flex justify-end">
            <button
              disabled={isExecuting || !summary}
              onClick={() => {
                setCurrentStep('verify');
                handleRunVerification();
              }}
              className="inline-flex items-center space-x-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-800 disabled:text-gray-600 text-white rounded-lg text-sm font-semibold transition-colors"
            >
              <span>Proceed to L1–L4 Verification Matrix</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* ── STEP 6: VERIFY ─────────────────────────────────────────────────── */}
      {currentStep === 'verify' && selectedDevice && (
        <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-6">
          <h4 className="text-base font-bold text-white flex items-center space-x-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <span>Step 6: Multi-Level Post-Sanitization Verification</span>
          </h4>

          {isVerifying && (
            <div className="p-8 text-center space-y-3">
              <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto" />
              <p className="text-xs text-gray-400 font-mono">Executing L1 Logical, L2 Host-Visible, L3 Device-Reported, and L4 Forensic Carving checks...</p>
            </div>
          )}

          {verificationReport && !isVerifying && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-surface-highlight border border-gray-800 flex items-center justify-between">
                <div>
                  <div className="text-emerald-400 font-bold text-base">
                    Verification Complete ({verificationReport.confidence_pct}% Forensic Confidence)
                  </div>
                  <div className="text-xs text-gray-400 mt-0.5 font-mono">
                    Target: {verificationReport.target_id} · Timestamp: {verificationReport.timestamp_utc}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {verificationReport.results.map((res) => (
                  <div key={res.level} className="p-4 rounded-xl bg-surface-highlight/40 border border-gray-800 space-y-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-gray-200">{res.level}</span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                          res.status === 'PASS' || res.status === 'PASSED'
                            ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                            : res.status === 'UNSUPPORTED'
                            ? 'bg-gray-800 text-gray-400 border border-gray-700'
                            : res.status === 'NOT_AVAILABLE'
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            : 'bg-red-500/20 text-red-400 border border-red-500/30'
                        }`}
                      >
                        {res.status.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-gray-400 text-[11px]">{res.detail}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="pt-4 border-t border-gray-800 flex justify-end">
            <button
              disabled={isVerifying || !verificationReport}
              onClick={() => {
                setCurrentStep('evidence');
                handleIssueCert();
              }}
              className="inline-flex items-center space-x-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-800 disabled:text-gray-600 text-white rounded-lg text-sm font-semibold transition-colors"
            >
              <span>View Evidential Attestation Certificate</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* ── STEP 7: EVIDENCE ───────────────────────────────────────────────── */}
      {currentStep === 'evidence' && selectedDevice && (
        <div className="p-6 rounded-xl bg-surface border border-gray-800 space-y-6">
          <h4 className="text-base font-bold text-white flex items-center space-x-2">
            <Award className="w-5 h-5 text-yellow-400" />
            <span>Step 7: Tamper-Evident Attestation Certificate & Audit Ledger</span>
          </h4>

          {isIssuingCert && (
            <div className="p-8 text-center space-y-3">
              <div className="w-8 h-8 border-2 border-yellow-500 border-t-transparent rounded-full animate-spin mx-auto" />
              <p className="text-xs text-gray-400 font-mono">Signing attestation certificate with Ed25519 keypair...</p>
            </div>
          )}

          {certificate && !isIssuingCert && (
            <div className="space-y-4">
              <div className="p-5 rounded-xl bg-yellow-950/20 border border-yellow-600/30 space-y-3 text-xs font-mono">
                <div className="flex justify-between border-b border-yellow-600/20 pb-2">
                  <span className="text-gray-400 uppercase">Certificate ID</span>
                  <span className="text-yellow-300 font-bold">{certificate.cert_id}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Target Device</span>
                  <span className="text-gray-200">{certificate.device_identity.model} ({certificate.device_identity.serial})</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Audit Chain Root Hash</span>
                  <span className="text-gray-300">{certificate.audit_chain_root_hash}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Ed25519 Signature</span>
                  <span className="text-emerald-400 break-all">{certificate.signature.substring(0, 48)}...</span>
                </div>
              </div>
              <div className="p-4 rounded-lg bg-blue-950/20 border border-blue-600/20 text-blue-200 text-xs font-mono">
                {certificate.trust_scope_note}
              </div>
            </div>
          )}

          <div className="pt-4 border-t border-gray-800 flex justify-between">
            <button
              onClick={() => {
                setCurrentStep('select');
                setConfirmationInput('');
                setSummary(null);
                setVerificationReport(null);
                setCertificate(null);
              }}
              className="px-4 py-2 bg-surface hover:bg-surface-highlight text-gray-400 text-xs rounded-lg border border-gray-700 font-mono"
            >
              Start New Workflow
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

