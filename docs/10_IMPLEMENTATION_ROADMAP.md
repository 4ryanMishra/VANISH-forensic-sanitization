# VANISH — Implementation Roadmap

## Phase 0 — Architecture
Repository, contracts, docs, CI and ownership.

## Phase 1 — Forensic MVP
Image reader, raw scanner, signatures, contiguous carving, validation and hashing.

## Phase 2 — Device MVP
Discovery, identity, boot detection and capability model. No destructive operations.

## Phase 3 — Policy simulator
Device → capabilities → policy → plan → simulation.

## Phase 4 — Fragment recovery
Candidate fragments, scoring, reconstruction, decoder validation and confidence.

## Phase 5 — Verification/audit
Verification model, audit events, hash chain and reports.

## Phase 6 — GUI
Dashboard, devices, recovery, sanitization, verification, audit, report and storage visualization.

## Phase 7 — Physical USB
Disposable SanDisk (16 GB, the only physical disposable media available —
see `08_PHYSICAL_LAB.md`); first recovery/read-only tests, then controlled
overwrite-based writes. No SSD/NVMe hardware Sanitize commands here — the
SanDisk does not expose them.

## Phase 8 — Device-specific sanitization
Only protocols actually exposed by tested hardware. Given current hardware
(SanDisk only, no SSD/NVMe, laptops excluded as targets), NVMe/SSD Sanitize
and Crypto Erase paths stay in Simulation mode against mocked capability
profiles until real hardware is available — see `08_PHYSICAL_LAB.md`.

## Phase 9 — Bootable environment
Reproducible Linux live environment.

## Phase 10 — Hardening
Unplugged device, identity change, permissions, corrupted media, unsupported filesystem/capability, report tampering, cancellation and crash recovery.

## Timeline

- 2 weeks: architecture + foundations
- 4–6 weeks: serious prototype
- 8–10 weeks: strong MVP
- 12–16 weeks: broader systems project

Hardware-specific work may extend the schedule.
