# VANISH — Master Agent Pack

VANISH is an integrated digital-forensics and storage-sanitization platform.

It combines two opposite workflows:
- **Forensic recovery:** determine whether deleted/damaged artifacts can still be recovered.
- **Sanitization:** execute an appropriate device-aware sanitization procedure and verify/report the result.

The novelty is the shared device abstraction, capability model, verification, hashing/provenance, audit trail, reporting and storage-stack visualization.

## Developers

Two developers, both using Antigravity: Aryan Mishra and Subodeep Mallick.
See `04_TEAM_SPLIT.md` for the current split — it has been revised down
from an earlier assumption of a larger bench.

- **Aryan:** device, platform, safety, policy, sanitization, verification, audit/attestation.
- **Subodeep:** forensic acquisition, filesystem analysis, carving, reconstruction, validation.
- **Shared:** common models, UI, integration, reports, documentation, final testing.

Hardware available: one 16 GB SanDisk USB drive. No dedicated SSD/NVMe.
Laptops are not destructive-test targets. See `08_PHYSICAL_LAB.md` for what
this does and doesn't change about scope.

## Build order

1. Architecture/contracts
2. Virtual-disk forensic laboratory
3. Device discovery
4. Sanitization policy simulation
5. Verification/audit
6. UI
7. Disposable physical-media testing
8. Bootable environment
9. End-to-end integration
10. Hardening

Read `01_MASTER_ENGINEERING_SPEC.md` before implementation. Read
`12_ATTESTATION_SPEC.md` before implementing the audit/signing module.
