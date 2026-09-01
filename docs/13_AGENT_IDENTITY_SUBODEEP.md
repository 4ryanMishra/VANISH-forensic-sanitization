# VANISH — Agent Identity: SUBODEEP

This file tells THIS Antigravity instance who it is working for. Read this
BEFORE `01_MASTER_ENGINEERING_SPEC.md` and before doing anything else,
including the architecture review in `11_AGENT_BOOTSTRAP_PROMPT.md`.

```text
AGENT_OWNER: Subodeep Mallick
ROLE: Forensics / Recovery  (see 04_TEAM_SPLIT.md → "Subodeep")
```

## You own (may create/edit freely)

```text
src-tauri/src/forensic/
  imaging/
  filesystem/
  carving/
  reconstruction/
  validation/
```

## You do NOT own — do not edit without Aryan's explicit agreement

```text
src-tauri/src/device/
src-tauri/src/platform/
src-tauri/src/policy/
src-tauri/src/sanitization/
src-tauri/src/deletion/
src-tauri/src/verification/
src-tauri/src/audit/
```

If a task seems to require changing something inside `device/`,
`sanitization/`, `verification/`, or `audit/`, stop and say so instead of
editing it. Flag it as a cross-boundary change that needs Aryan's sign-off
— do not silently patch it, even if the fix looks small or obvious.

## Shared — editable, but changes need agreement from both

```text
src-tauri/src/common/
src/                    // frontend
tests/integration/
docs/
```

Modifying anything in `common/` or a shared API contract
(`06_API_CONTRACTS.md`) without Aryan's agreement is the #1 way a
two-person team loses a day to a merge conflict. Propose the change, don't
just make it.

## Build order (your subsystems, in sequence)

1. read-only image reader
2. filesystem analysis
3. raw scanner
4. signature registry
5. contiguous carving
6. fragment candidate model
7. fragment reconstruction
8. format-aware validation
9. hashing/provenance — feeds `RecoveredArtifact` into Aryan's attestation
   module (`12_ATTESTATION_SPEC.md`); do not build a second/separate
   signing path for recovery results
10. recovery metrics

## Hardware you're working against

One 16 GB SanDisk USB drive (real, disposable). This is genuinely enough
for your track — filesystem deletion/recovery, raw scanning, and carving
all work on real flash hardware without needing NVMe/SSD-specific
commands. No SSD/NVMe device available; laptops are never a destructive
target. Full detail in `08_PHYSICAL_LAB.md`.
