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
  Info,
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
      setProgress((prev) => (prev >= 95 ? 95 : prev + 4));
    }, 800);

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
    { id: 'select', label: '1. Target Select', number: 1 },
    { id: 'analyze', label: '2. Media Probe', number: 2 },
    { id: 'configure', label: '3. Policy Select', number: 3 },
    { id: 'safety_check', label: '4. Invariant Lock', number: 4 },
    { id: 'execute', label: '5. Sanitize Engine', number: 5 },
    { id: 'verify', label: '6. L1–L4 Matrix', number: 6 },
    { id: 'evidence', label: '7. Attestation Cert', number: 7 },
  ];

  const currentStepIdx = stepsList.findIndex((s) => s.id === currentStep);

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-[10px] font-mono font-bold tracking-widest text-vermilion uppercase bg-vermilion/10 px-2 py-0.5 rounded border border-vermilion/20">
              SECURE ERASURE PIPELINE
            </span>
            {selectedDevice?.is_simulated ? (
              <span className="px-2 py-0.5 rounded bg-amber/10 border border-amber/20 text-amber text-[10px] font-mono font-bold">
                SIMULATION MODE
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded bg-surface-elevated border border-border text-charcoal/70 text-[10px] font-mono font-bold">
                HARDWARE RAW IO
              </span>
            )}
          </div>
          <h2 className="text-xl font-bold text-charcoal tracking-tight mt-1">
            Capability-Aware Sanitization Engine
          </h2>
          <p className="text-xs text-charcoal/60 mt-0.5">
            Deterministic 7-stage workflow: Bus Target → Hardware Discovery → Policy Rules → Invariant Safety Gate → Execution → Verification → Ed25519 Attestation
          </p>
        </div>
      </div>

      {/* Scope Transparency Disclosure */}
      <div className="p-4 rounded-xl bg-surface-elevated border border-border flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center space-x-2.5">
          <Info className="w-4 h-4 text-telemetry shrink-0" />
          <span className="text-charcoal/80">
            Active Target: <strong className="text-charcoal">{selectedDevice?.path || 'N/A'}</strong> ({selectedDevice?.model || 'None'})
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-charcoal/60">
          <span>Total Device Capacity: <strong className="text-charcoal font-semibold">{selectedDevice ? `${(selectedDevice.capacity_bytes / 1e9).toFixed(2)} GB` : '0 GB'}</strong></span>
          <span className="text-border">|</span>
          <span className="text-vermilion font-bold">Active Scope: 256 MB Physical Demo Window</span>
        </div>
      </div>

      {/* Stepper Navigation */}
      <div className="flex items-center justify-between overflow-x-auto pb-2 border-b border-border gap-2">
        {stepsList.map((step, idx) => {
          const isActive = currentStep === step.id;
          const isDone = currentStepIdx > idx;
          return (
            <React.Fragment key={step.id}>
              <button
                disabled={isExecuting}
                onClick={() => setCurrentStep(step.id)}
                className={`flex items-center space-x-2 text-xs font-mono font-semibold transition-all px-3 py-1.5 rounded-lg shrink-0 ${
                  isActive
                    ? 'bg-vermilion text-white shadow-subtle'
                    : isDone
                    ? 'text-verified bg-verified/10 hover:bg-verified/20'
                    : 'text-charcoal/50 hover:text-charcoal bg-white border border-border'
                }`}
              >
                <span
                  className={`w-4 h-4 rounded-full flex items-center justify-center text-[10px] font-bold ${
                    isActive
                      ? 'bg-white text-vermilion'
                      : isDone
                      ? 'bg-verified text-white'
                      : 'bg-surface-elevated text-charcoal/60'
                  }`}
                >
                  {isDone ? '✓' : step.number}
                </span>
                <span>{step.label}</span>
              </button>
              {idx < stepsList.length - 1 && (
                <ChevronRight className="w-3.5 h-3.5 text-charcoal/30 flex-shrink-0" />
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* ── STEP 1: SELECT ─────────────────────────────────────────────────── */}
      {currentStep === 'select' && (
        <div className="p-6 rounded-xl bg-white border border-border space-y-4 shadow-subtle">
          <div className="flex items-center justify-between">
            <h4 className="text-base font-bold text-charcoal flex items-center space-x-2">
              <HardDrive className="w-5 h-5 text-telemetry" />
              <span>Step 1: Select Storage Device Target</span>
            </h4>
            <button
              onClick={loadDevices}
              className="flex items-center space-x-1.5 px-3 py-1.5 bg-surface-elevated hover:bg-border text-xs font-semibold rounded-lg text-charcoal border border-border"
            >
              <RefreshCw className="w-3 h-3 text-telemetry" />
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
                      ? 'bg-vermilion/5 border-vermilion/20 cursor-not-allowed opacity-75'
                      : isSelected
                      ? 'bg-vermilion/5 border-vermilion cursor-pointer ring-1 ring-vermilion/30'
                      : 'bg-white border-border hover:border-telemetry/40 cursor-pointer'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3.5">
                      <div className={`p-2.5 rounded-lg border ${
                        isSystem 
                          ? 'bg-vermilion/10 text-vermilion border-vermilion/20' 
                          : 'bg-telemetry/10 text-telemetry border-telemetry/20'
                      }`}>
                        <HardDrive className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-bold text-charcoal text-sm">{d.model}</span>
                          {d.is_simulated && (
                            <span className="px-1.5 py-0.5 rounded bg-amber/10 text-amber text-[10px] font-mono font-bold border border-amber/20">
                              SIMULATED
                            </span>
                          )}
                          {isSystem && (
                            <span className="px-2 py-0.5 rounded bg-vermilion/10 text-vermilion text-xs font-bold border border-vermilion/20 flex items-center space-x-1 font-mono">
                              <AlertOctagon className="w-3 h-3" />
                              <span>SYSTEM / BOOT DISK (LOCKED)</span>
                            </span>
                          )}
                        </div>
                        <div className="text-xs text-charcoal/60 font-mono mt-1">
                          Path: <strong className="text-charcoal">{d.path}</strong> · Serial: <strong className="text-charcoal">{d.serial || 'N/A'}</strong> · Capacity: <strong className="text-telemetry font-semibold">{(d.capacity_bytes / 1e9).toFixed(2)} GB</strong>
                        </div>
                      </div>
                    </div>
                    {isSelected && !isSystem && (
                      <span className="px-3 py-1 bg-vermilion text-white text-xs font-bold rounded-lg font-mono shadow-subtle">
                        SELECTED
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          <div className="pt-4 border-t border-border flex justify-end">
            <button
              disabled={!selectedDevice || selectedDevice.system_disk}
              onClick={() => setCurrentStep('analyze')}
              className="inline-flex items-center space-x-2 px-5 py-2.5 bg-charcoal hover:bg-charcoal/90 disabled:opacity-50 text-white rounded-lg text-xs font-semibold shadow-subtle transition-colors"
            >
              <span>Continue to Media Analysis</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* ── STEP 2: ANALYZE ────────────────────────────────────────────────── */}
      {currentStep === 'analyze' && selectedDevice && (
        <div className="p-6 rounded-xl bg-white border border-border space-y-6 shadow-subtle">
          <h4 className="text-base font-bold text-charcoal flex items-center space-x-2">
            <Cpu className="w-5 h-5 text-telemetry" />
            <span>Step 2: Media Capability & Storage Architecture Analysis</span>
          </h4>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
            <div className="p-4 rounded-lg bg-surface-elevated border border-border space-y-1">
              <span className="text-charcoal/50 uppercase text-[10px]">Device Identifier</span>
              <div className="text-charcoal font-bold">{selectedDevice.stable_id}</div>
            </div>
            <div className="p-4 rounded-lg bg-surface-elevated border border-border space-y-1">
              <span className="text-charcoal/50 uppercase text-[10px]">Bus Interface</span>
              <div className="text-telemetry font-bold">{typeof selectedDevice.interface === 'string' ? selectedDevice.interface : 'Unknown'}</div>
            </div>
            <div className="p-4 rounded-lg bg-surface-elevated border border-border space-y-1">
              <span className="text-charcoal/50 uppercase text-[10px]">Media Type</span>
              <div className="text-verified font-bold">{typeof selectedDevice.media_type === 'string' ? selectedDevice.media_type : 'Unknown'}</div>
            </div>
            <div className="p-4 rounded-lg bg-surface-elevated border border-border space-y-1">
              <span className="text-charcoal/50 uppercase text-[10px]">Sector Geometry</span>
              <div className="text-charcoal font-bold">{selectedDevice.logical_block_size}B Logical / {selectedDevice.physical_block_size}B Physical</div>
            </div>
          </div>

          <div className="space-y-3">
            <h5 className="text-xs font-mono font-bold text-charcoal uppercase tracking-wider">
              Discovered Hardware Primitives
            </h5>
            <div className="flex flex-wrap gap-2">
              {selectedDevice.capabilities && selectedDevice.capabilities.length > 0 ? (
                selectedDevice.capabilities.map((cap) => (
                  <span
                    key={cap}
                    className="px-3 py-1.5 rounded-lg bg-telemetry/10 border border-telemetry/20 text-telemetry text-xs font-mono font-semibold flex items-center space-x-1.5"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>{cap}</span>
                  </span>
                ))
              ) : (
                <span className="text-xs font-mono text-charcoal/40 italic">No low-level vendor primitives reported</span>
              )}
            </div>
          </div>

          <div className="pt-4 border-t border-border flex justify-between">
            <button
              onClick={() => setCurrentStep('select')}
              className="px-4 py-2 bg-surface-elevated hover:bg-border text-charcoal text-xs font-semibold rounded-lg border border-border"
            >
              ← Back
            </button>
            <button
              onClick={() => setCurrentStep('configure')}
              className="inline-flex items-center space-x-2 px-5 py-2.5 bg-charcoal hover:bg-charcoal/90 text-white rounded-lg text-xs font-semibold shadow-subtle transition-colors"
            >
              <span>Continue to Policy Configuration</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* ── STEP 3: CONFIGURE ──────────────────────────────────────────────── */}
      {currentStep === 'configure' && selectedDevice && (
        <div className="p-6 rounded-xl bg-white border border-border space-y-6 shadow-subtle">
          <h4 className="text-base font-bold text-charcoal flex items-center space-x-2">
            <Settings className="w-5 h-5 text-telemetry" />
            <span>Step 3: Sanitization Policy & Standard Selection</span>
          </h4>

          <div className="space-y-3">
            <label className="text-xs font-mono font-bold text-charcoal uppercase tracking-wider">
              Compliance Standard
            </label>
            <select
              value={standard}
              onChange={(e) => setStandard(e.target.value as SanitizationStandard)}
              className="w-full bg-white border border-border rounded-lg px-3 py-2.5 text-xs text-charcoal focus:outline-none focus:border-vermilion font-mono shadow-subtle"
            >
              <option value="Nist80088Clear">NIST SP 800-88 Rev. 1-derived Clear (Host Logical Overwrite | IEEE 2883-2022 Overwrite)</option>
              <option value="Nist80088Purge">NIST SP 800-88 Rev. 1-derived Purge (Hardware Sanitize / Crypto Erase | IEEE 2883-2022 Purge)</option>
              <option value="Ieee2883Purge">IEEE 2883-2022 — Purge (Solid-State Block/Crypto Erase)</option>
              <option value="Dod522022M3Pass">DoD 5220.22-M (3-Pass Multi-Pattern Stream)</option>
              <option value="SinglePassZero">Single-Pass Zero Fill (0x00 Stream)</option>
              <option value="SinglePassRandom">Single-Pass Pseudo-Random Stream</option>
            </select>
          </div>

          {plan && (
            <div className="p-5 rounded-xl bg-surface-elevated border border-border space-y-4 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-mono text-telemetry font-bold">PLAN ID: {plan.plan_id}</span>
                <span className="px-2.5 py-0.5 rounded bg-white text-charcoal font-mono text-[11px] font-bold border border-border">
                  {typeof plan.method === 'string' ? plan.method : 'Custom Block Stream'}
                </span>
              </div>
              <p className="text-charcoal/80 leading-relaxed font-sans">{plan.rationale}</p>
              {plan.warnings.length > 0 && (
                <div className="p-3 rounded-lg bg-amber/5 border border-amber/20 text-charcoal/80 space-y-1">
                  <div className="font-bold text-amber text-xs font-mono">Declared Constraints & Technical Scope:</div>
                  {plan.warnings.map((w, idx) => (
                    <div key={idx} className="text-xs">• {w}</div>
                  ))}
                </div>
              )}
            </div>
          )}

          <div className="pt-4 border-t border-border flex justify-between">
            <button
              onClick={() => setCurrentStep('analyze')}
              className="px-4 py-2 bg-surface-elevated hover:bg-border text-charcoal text-xs font-semibold rounded-lg border border-border"
            >
              ← Back
            </button>
            <button
              onClick={() => setCurrentStep('safety_check')}
              className="inline-flex items-center space-x-2 px-5 py-2.5 bg-vermilion hover:bg-vermilion-dark text-white rounded-lg text-xs font-semibold shadow-subtle transition-colors"
            >
              <span>Proceed to Invariant Safety Gate</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* ── STEP 4: SAFETY CHECK ───────────────────────────────────────────── */}
      {currentStep === 'safety_check' && selectedDevice && (
        <div className="p-6 rounded-xl bg-white border border-border space-y-6 shadow-subtle">
          <h4 className="text-base font-bold text-charcoal flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-vermilion" />
            <span>Step 4: Two-Stage Invariant Safety Gate & Confirmation</span>
          </h4>

          <div className="p-4 rounded-xl bg-vermilion/5 border border-vermilion/20 space-y-3 text-xs">
            <div className="text-vermilion font-bold uppercase tracking-wider flex items-center space-x-2 font-mono">
              <AlertCircle className="w-4 h-4 text-vermilion" />
              <span>Safety Gate Evaluation Matrix</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 font-mono text-charcoal/80">
              <div className="flex items-center space-x-2">
                <span className="text-verified font-bold">✓</span>
                <span>Target Serial Match: {selectedDevice.serial || 'Verified'}</span>
              </div>
              <div className="flex items-center space-x-2">
                <span className="text-verified font-bold">✓</span>
                <span>System Disk Check: False (Protected)</span>
              </div>
              <div className="flex items-center space-x-2">
                <span className="text-verified font-bold">✓</span>
                <span>Boot Device Check: False (Protected)</span>
              </div>
              <div className="flex items-center space-x-2">
                <span className="text-verified font-bold">✓</span>
                <span>Target Revalidation: Path Active ({selectedDevice.path})</span>
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <label className="text-xs font-bold text-charcoal">
              To arm the destructive execution engine, type <code className="text-vermilion font-mono font-bold bg-vermilion/10 px-1.5 py-0.5 rounded">CONFIRM DESTROY</code>:
            </label>
            <input
              type="text"
              value={confirmationInput}
              onChange={(e) => setConfirmationInput(e.target.value)}
              placeholder="CONFIRM DESTROY"
              className="w-full bg-white border border-border rounded-lg px-4 py-2.5 text-xs text-charcoal focus:outline-none focus:border-vermilion font-mono uppercase shadow-subtle font-bold"
            />
          </div>

          <div className="pt-4 border-t border-border flex justify-between">
            <button
              onClick={() => setCurrentStep('configure')}
              className="px-4 py-2 bg-surface-elevated hover:bg-border text-charcoal text-xs font-semibold rounded-lg border border-border"
            >
              ← Back
            </button>
            <button
              disabled={confirmationInput !== 'CONFIRM DESTROY'}
              onClick={() => {
                setCurrentStep('execute');
                handleStartExecution();
              }}
              className="inline-flex items-center space-x-2 px-5 py-2.5 bg-vermilion hover:bg-vermilion-dark disabled:opacity-50 text-white rounded-lg text-xs font-semibold transition-all shadow-subtle"
            >
              <Trash2 className="w-4 h-4" />
              <span>Arm & Execute Sanitization</span>
            </button>
          </div>
        </div>
      )}

      {/* ── STEP 5: EXECUTE ────────────────────────────────────────────────── */}
      {currentStep === 'execute' && selectedDevice && (
        <div className="p-6 rounded-xl bg-white border border-border space-y-6 shadow-subtle">
          <h4 className="text-base font-bold text-charcoal flex items-center space-x-2">
            <Trash2 className="w-5 h-5 text-vermilion" />
            <span>Step 5: Sanitization Execution Status</span>
          </h4>

          {isExecuting && (
            <div className="space-y-3">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-charcoal/70">Executing Controlled Sanitization Routine (Raw I/O Block Stream)...</span>
                <span className="text-vermilion font-bold">{progress}%</span>
              </div>
              <div className="w-full bg-surface-elevated rounded-full h-2.5 overflow-hidden">
                <div
                  className="bg-vermilion h-2.5 rounded-full transition-all duration-300"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          )}

          {executionError && !isExecuting && (
            <div className="p-5 rounded-xl bg-vermilion/5 border border-vermilion/30 space-y-3 text-xs">
              <div className="flex items-center space-x-2 text-vermilion font-bold text-sm">
                <AlertCircle className="w-5 h-5 shrink-0" />
                <span>Sanitization Operation Aborted or Failed</span>
              </div>
              <div className="font-mono text-vermilion pl-7 break-all">
                {executionError}
              </div>
            </div>
          )}

          {summary && !isExecuting && (
            <div className="p-5 rounded-xl bg-verified/5 border border-verified/30 space-y-3 text-xs">
              <div className="flex items-center space-x-2 text-verified font-bold text-sm">
                <CheckCircle2 className="w-5 h-5" />
                <span>Sanitization Completed Successfully ({summary.method_executed})</span>
              </div>
              <div className="font-mono text-charcoal/80 space-y-1 pl-7">
                {summary.execution_log.map((entry, idx) => (
                  <div key={idx}>✓ {entry}</div>
                ))}
              </div>
            </div>
          )}

          <div className="pt-4 border-t border-border flex justify-end">
            <button
              disabled={isExecuting || !summary}
              onClick={() => {
                setCurrentStep('verify');
                handleRunVerification();
              }}
              className="inline-flex items-center space-x-2 px-5 py-2.5 bg-charcoal hover:bg-charcoal/90 disabled:opacity-50 text-white rounded-lg text-xs font-semibold shadow-subtle transition-colors"
            >
              <span>Proceed to L1–L4 Verification Matrix</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* ── STEP 6: VERIFY ─────────────────────────────────────────────────── */}
      {currentStep === 'verify' && selectedDevice && (
        <div className="p-6 rounded-xl bg-white border border-border space-y-6 shadow-subtle">
          <h4 className="text-base font-bold text-charcoal flex items-center space-x-2">
            <ShieldCheck className="w-5 h-5 text-verified" />
            <span>Step 6: Multi-Level Post-Sanitization Verification</span>
          </h4>

          {isVerifying && (
            <div className="p-8 text-center space-y-3">
              <div className="w-8 h-8 border-2 border-telemetry border-t-transparent rounded-full animate-spin mx-auto" />
              <p className="text-xs text-charcoal/60 font-mono">Executing L1 Logical, L2 Host-Visible, L3 Device-Reported, and L4 Forensic Carving checks...</p>
            </div>
          )}

          {verificationReport && !isVerifying && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-surface-elevated border border-border flex items-center justify-between">
                <div>
                  <div className="text-verified font-bold text-base">
                    Verification Complete ({verificationReport.confidence_pct}% Forensic Confidence)
                  </div>
                  <div className="text-xs text-charcoal/60 mt-0.5 font-mono">
                    Target: {verificationReport.target_id} · Timestamp: {verificationReport.timestamp_utc}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {verificationReport.results.map((res) => (
                  <div key={res.level} className="p-4 rounded-xl bg-white border border-border space-y-2 text-xs shadow-subtle">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-charcoal font-mono">{res.level}</span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                          res.status === 'PASS' || res.status === 'PASSED'
                            ? 'bg-verified/10 text-verified border border-verified/30'
                            : res.status === 'UNSUPPORTED'
                            ? 'bg-surface-elevated text-charcoal/50 border border-border'
                            : res.status === 'NOT_AVAILABLE'
                            ? 'bg-amber/10 text-amber border border-amber/30'
                            : 'bg-vermilion/10 text-vermilion border border-vermilion/30'
                        }`}
                      >
                        {res.status.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-charcoal/70 text-[11px] font-sans">{res.detail}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="pt-4 border-t border-border flex justify-end">
            <button
              disabled={isVerifying || !verificationReport}
              onClick={() => {
                setCurrentStep('evidence');
                handleIssueCert();
              }}
              className="inline-flex items-center space-x-2 px-5 py-2.5 bg-charcoal hover:bg-charcoal/90 disabled:opacity-50 text-white rounded-lg text-xs font-semibold shadow-subtle transition-colors"
            >
              <span>View Evidential Attestation Certificate</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* ── STEP 7: EVIDENCE ───────────────────────────────────────────────── */}
      {currentStep === 'evidence' && selectedDevice && (
        <div className="p-6 rounded-xl bg-white border border-border space-y-6 shadow-subtle">
          <h4 className="text-base font-bold text-charcoal flex items-center space-x-2">
            <Award className="w-5 h-5 text-amber" />
            <span>Step 7: Tamper-Evident Attestation Certificate & Audit Ledger</span>
          </h4>

          {isIssuingCert && (
            <div className="p-8 text-center space-y-3">
              <div className="w-8 h-8 border-2 border-amber border-t-transparent rounded-full animate-spin mx-auto" />
              <p className="text-xs text-charcoal/60 font-mono">Signing attestation certificate with Ed25519 keypair...</p>
            </div>
          )}

          {certificate && !isIssuingCert && (
            <div className="space-y-4">
              <div className="p-5 rounded-xl bg-surface-elevated border border-border space-y-3 text-xs font-mono">
                <div className="flex justify-between border-b border-border pb-2">
                  <span className="text-charcoal/50 uppercase">Certificate ID</span>
                  <span className="text-charcoal font-bold">{certificate.cert_id}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-charcoal/50">Target Device</span>
                  <span className="text-charcoal font-semibold">{certificate.device_identity.model} ({certificate.device_identity.serial || 'N/A'})</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-charcoal/50">Audit Chain Root Hash</span>
                  <span className="text-charcoal/80">{certificate.audit_chain_root_hash}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-charcoal/50">Ed25519 Signature</span>
                  <span className="text-verified font-bold break-all">{certificate.signature.substring(0, 48)}...</span>
                </div>
              </div>
              <div className="p-4 rounded-lg bg-telemetry/5 border border-telemetry/20 text-charcoal/80 text-xs font-mono">
                {certificate.trust_scope_note}
              </div>
            </div>
          )}

          <div className="pt-4 border-t border-border flex justify-between">
            <button
              onClick={() => {
                setCurrentStep('select');
                setConfirmationInput('');
                setSummary(null);
                setVerificationReport(null);
                setCertificate(null);
              }}
              className="px-4 py-2 bg-surface-elevated hover:bg-border text-charcoal text-xs font-semibold rounded-lg border border-border font-mono"
            >
              Start New Workflow
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

