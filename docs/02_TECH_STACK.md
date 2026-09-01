# VANISH — Technology Stack

| Layer | Technology |
|---|---|
| Systems core | Rust |
| GUI shell | Tauri |
| Frontend | React + TypeScript |
| IPC | Tauri commands/events |
| Serialization | serde / JSON |
| Hashing | Rust cryptographic library |
| Testing | Rust unit/integration + frontend tests |
| Lab environment | Linux live environment |
| Version control | Git |

## Backend

```text
device
platform
policy
sanitization
deletion
verification
audit
reporting
forensic/
  imaging
  filesystem
  carving
  reconstruction
  validation
common/
```

## UI

```text
Dashboard
Devices
Forensic Recovery
Sanitization
Verification
Audit Trail
Reports
Laboratory / Simulation
```

The frontend never directly performs raw-device operations. Safety-sensitive behavior belongs to the Rust backend.
