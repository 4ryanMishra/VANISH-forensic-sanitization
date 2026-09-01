# VANISH — Two-Person Antigravity Work Split

Team: Aryan Mishra and Subodeep Mallick. Both use Antigravity. Other team
members (Sai Srikanth, Shivansh Chugh, B. Nethra, Nandini Anuradha
Nithyanandh) are not writing code against this repo — pitch, docs, testing
support, and non-engineering deliverables are their track and out of scope
for this file.

Two people, ten-plus subsystems in `01_MASTER_ENGINEERING_SPEC.md` — the
split below is deliberately narrow. Do not both start "helping" on the
other's subsystem without agreement; that's how a two-person team loses
time to merge conflicts instead of building.

## Aryan — Device / Sanitization / Attestation

Own:

```text
src-tauri/src/device/
src-tauri/src/platform/
src-tauri/src/policy/
src-tauri/src/sanitization/
src-tauri/src/deletion/
src-tauri/src/verification/
src-tauri/src/audit/          // includes 12_ATTESTATION_SPEC.md
```

Build, in order:
1. device discovery
2. device identity
3. boot/system detection
4. capability discovery
5. policy engine
6. safety gate
7. sanitization plan
8. execution adapters
9. verification
10. audit + attestation (signing, cert issuance — see `12_ATTESTATION_SPEC.md`)

## Subodeep — Forensics / Recovery

Own:

```text
src-tauri/src/forensic/
  imaging/
  filesystem/
  carving/
  reconstruction/
  validation/
```

Build, in order:
1. read-only image reader
2. filesystem analysis
3. raw scanner
4. signature registry
5. contiguous carving
6. fragment candidate model
7. fragment reconstruction
8. format-aware validation
9. hashing/provenance (feeds into Aryan's attestation module — do not build
   a second signing path)
10. recovery metrics

## Shared

```text
src-tauri/src/common/
src/                    // frontend — split by page/feature, agree before touching shared components
tests/integration/
docs/
```

Shared interfaces (`06_API_CONTRACTS.md`) require agreement from both
before modification — this is the one rule that actually matters with only
two people, since there's no third reviewer to catch a silent breaking
change.

## Realistic scope note

The original spec assumed enough hands to build forensic recovery,
sanitization, verification, audit, attestation, and a bootable environment
in parallel. With two people, treat `10_IMPLEMENTATION_ROADMAP.md`'s
Phase 7–9 (physical USB, device-specific sanitization beyond what's tested,
bootable live environment) as stretch goals, not committed scope — see the
updated `08_PHYSICAL_LAB.md` for what's realistic given available hardware.
Prioritize Phases 0–6 (simulation, virtual disk, policy, recovery,
verification/audit, GUI) as the actual deliverable; those alone are a
complete, demoable, judge-defensible product even with zero physical writes.

## Branches

```text
main
feature/device
feature/sanitization
feature/forensics
feature/reconstruction
feature/ui
feature/integration
```

## Merge order

1. common models
2. foundations
3. policy/recovery engines
4. verification/audit
5. UI
6. integration
7. physical adapters (if reached)
