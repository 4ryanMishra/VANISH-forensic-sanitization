# VANISH — Master Engineering Specification

## 1. Product

VANISH is a systems-level platform for secure storage sanitization and forensic recovery.

It provides:
- device discovery;
- capability-aware sanitization;
- targeted deletion workflows;
- read-only forensic analysis;
- file carving and reconstruction;
- artifact validation;
- hashing/provenance;
- verification;
- tamper-evident audit;
- reporting;
- GUI;
- controlled bootable laboratory environment.

## 2. Fundamental storage model

```text
Application
    ↓
Filesystem
    ↓
Logical blocks
    ↓
Storage controller / FTL
    ↓
Physical media
```

The platform must reason about these layers rather than treating every device as a simple byte array.

## 3. System architecture

```text
┌───────────────────────────────────────────┐
│                 VANISH UI                 │
│ Dashboard | Recovery | Sanitization | Log │
└─────────────────────┬─────────────────────┘
                      ↓
┌───────────────────────────────────────────┐
│              ORCHESTRATOR                 │
│ Jobs | Policy | State | Safety Gates      │
└───────────────┬─────────────────┬─────────┘
                ↓                 ↓
      ┌─────────────────┐ ┌─────────────────┐
      │ FORENSIC ENGINE │ │ SANITIZATION    │
      │ Acquisition     │ │ Capability      │
      │ Filesystem      │ │ Policy          │
      │ Carving         │ │ Execution       │
      │ Reconstruction  │ │ Verification    │
      │ Validation      │ │                 │
      └────────┬────────┘ └────────┬────────┘
               └──────────┬────────┘
                          ↓
                 ┌──────────────────┐
                 │ EVIDENCE / AUDIT│
                 │ Hashes           │
                 │ Provenance       │
                 │ Audit chain      │
                 │ Reports          │
                 └────────┬─────────┘
                          ↓
                 ┌──────────────────┐
                 │ PLATFORM LAYER   │
                 │ Linux / Windows  │
                 │ Storage APIs     │
                 └──────────────────┘
```

## 4. Device abstraction

```text
Device
├── stable_id
├── path
├── model
├── serial
├── capacity
├── logical_block_size
├── physical_block_size
├── interface
├── media_type
├── mounted
├── boot_device
├── read_only
└── capabilities[]
```

Capabilities must be discovered, not guessed.

## 5. Execution modes

### Simulation
Virtual disk images and mocked devices. No physical writes.

### Forensic
Read-only physical source or forensic image. No writes to evidence.

### Sanitization
Explicitly armed disposable target. Identity is rechecked immediately before execution.

## 6. Recovery

```text
Source
 ↓
Read-only acquisition/image
 ↓
Filesystem analysis
 ↓
Raw scan
 ↓
Signature candidate
 ↓
Contiguous OR fragmented reconstruction
 ↓
Format-aware validation
 ↓
Hash
 ↓
Recovered artifact + provenance
 ↓
Report
```

### Contiguous recovery

Detect a supported magic header, determine a format-appropriate candidate boundary, construct the candidate, validate it with a parser/decoder, then hash and record provenance.

### Fragmented recovery

```text
Fragment A
 ↓
Candidate fragments
 ↓
Hypothesis generation
 ↓
Scoring
 ↓
In-memory reconstruction
 ↓
Decoder validation
 ↓
Confidence/result
```

Possible signals include format structure, alignment, continuity, expected size, checksums and decoder success. Entropy is only a supporting signal.

## 7. Sanitization

```text
Device discovery
 ↓
Identity
 ↓
Capability discovery
 ↓
Policy engine
 ↓
Sanitization plan
 ↓
Safety gate
 ↓
Execution adapter
 ↓
Verification
 ↓
Audit/report
```

### HDD
Use an explicitly documented appropriate sanitization method according to the selected policy and applicable guidance. Do not hard-code the claim that a particular pass count universally guarantees sanitization.

### SSD/NVMe
SSD behavior involves FTL, wear leveling, garbage collection, over-provisioning and remapping. Host overwrite cannot automatically be treated as physical NAND-cell control.

Prefer device-supported sanitization mechanisms when appropriate and available.

### USB flash
A generic USB flash drive is not automatically NVMe. The 16 GB SanDisk is suitable as disposable laboratory media for controlled experiments, but NVMe-specific functionality requires actual NVMe-capable hardware.

## 8. Targeted deletion

VANISH distinguishes:

```text
Logical deletion
        ≠
Physical/device sanitization
```

Possible remnants include content, metadata, slack, journals, caches, snapshots and controller-managed copies.

Host-level targeted deletion cannot universally prove every historical physical representation on modern flash has disappeared.

## 9. Verification

### L1 — Logical
Filesystem no longer exposes target.

### L2 — Host-visible
Defined raw/logical scan does not find target.

### L3 — Device-reported
Device reports completion of supported mechanism.

### L4 — Forensic validation
VANISH's defined recovery pipeline cannot recover/validate the target.

A report must state exactly which levels were achieved.

## 10. Evidence/audit

```text
AuditEvent
├── event_id
├── timestamp
├── actor
├── operation
├── target_id
├── parameters
├── result
├── verification
├── error
└── previous_event_hash
```

Hash-linked events create a tamper-evident audit chain.

## 11. Report

Include case ID, device identity, capabilities, operation, policy, timeline, execution result, verification, recovered artifacts, hashes, audit chain, warnings and limitations.

Preferred wording:

> No target artifact was recovered by the specified VANISH validation procedure.

Avoid universal claims such as "nobody can ever recover this data."
