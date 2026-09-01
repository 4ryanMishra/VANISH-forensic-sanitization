# Current Work Status

## Agent A (Aryan Mishra)
- **Status:** Active — Repository Initialized & Scoped
- **Role:** Device / Platform / Policy / Sanitization / Deletion / Verification / Audit & Attestation
- **Branch:** main
- **Hardware Targets:**
  - Physical: 16 GB SanDisk USB flash drive (HostBlockOverwrite, file deletion vs sanitization demo)
  - Simulated: Enterprise NVMe SSD & Virtual Disk Images (real ATA/NVMe Sanitize command layer executed against simulated target)
  - Host System: Write-locked & protected by invariant safety gates
- **Blocked by:** None
- **Next:** Implement Linux & Windows device discovery adapters and NVMe/ATA sanitize command construction layer

## Agent B (Subodeep Mallick)
- **Status:** Ready
- **Role:** Forensic Acquisition / Filesystem Analysis / Signature Carving / Fragmented Reconstruction / Validation
- **Branch:** main
- **Blocked by:** None
- **Next:** Implement virtual disk raw reader and JPEG/PDF signature carver

## Shared
- **Contracts:** Frozen in `src-tauri/src/common/` and `src/types/index.ts` (aligned with `docs/06_API_CONTRACTS.md`)
- **Known conflicts:** None
