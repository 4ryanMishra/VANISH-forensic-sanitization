# VANISH — Agent Identity: ARYAN

This file tells THIS Antigravity instance who it is working for. Read this
BEFORE `01_MASTER_ENGINEERING_SPEC.md` and before doing anything else,
including the architecture review in `11_AGENT_BOOTSTRAP_PROMPT.md`.

```text
AGENT_OWNER: Aryan Mishra
ROLE: Device / Sanitization / Attestation  (see 04_TEAM_SPLIT.md → "Aryan")
```

## You own (may create/edit freely)

```text
src-tauri/src/device/
src-tauri/src/platform/
src-tauri/src/policy/
src-tauri/src/sanitization/
src-tauri/src/deletion/
src-tauri/src/verification/
src-tauri/src/audit/          // includes attestation — see 12_ATTESTATION_SPEC.md
```

## You do NOT own — do not edit without Subodeep's explicit agreement

```text
src-tauri/src/forensic/
  imaging/
  filesystem/
  carving/
  reconstruction/
  validation/
```

If a task seems to require changing something inside `forensic/`, stop and
say so instead of editing it. Flag it as a cross-boundary change that needs
Subodeep's sign-off — do not silently patch it, even if the fix looks small
or obvious.

## Shared — editable, but changes need agreement from both

```text
src-tauri/src/common/
src/                    // frontend
tests/integration/
docs/
```

Modifying anything in `common/` or a shared API contract
(`06_API_CONTRACTS.md`) without Subodeep's agreement is the #1 way a
two-person team loses a day to a merge conflict. Propose the change, don't
just make it.

## Build order (your subsystems, in sequence)

1. device discovery
2. device identity
3. boot/system detection
4. capability discovery
5. policy engine
6. safety gate
7. sanitization plan
8. execution adapters — including the real NVMe/SSD hardware sanitize
   command layer (ATA SECURITY ERASE UNIT / SANITIZE DEVICE, NVMe
   Format NVM / Sanitize) run against Simulation-mode mocked devices;
   see `08_PHYSICAL_LAB.md` for what's real-hardware-testable vs.
   simulation-only given available equipment
9. verification
10. audit + attestation (signing, cert issuance — see `12_ATTESTATION_SPEC.md`)

## Hardware you're working against

One 16 GB SanDisk USB drive (real, disposable). No SSD/NVMe device
available. Laptops are never a destructive target. Full detail in
`08_PHYSICAL_LAB.md` — but note: the command-construction code for
NVMe/SSD Sanitize is real and should be built in full; only the physical
target for those specific commands is simulated, not the code itself.
