# VANISH — Integrated Storage Sanitization & Digital Forensics Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Architecture: Tauri+Rust+React](https://img.shields.io/badge/Stack-Tauri%20%7C%20Rust%20%7C%20React%20%7C%20TypeScript-informational)](#)

VANISH is an enterprise and lab-grade integrated digital-forensics and storage-sanitization platform. It provides capability-aware device sanitization, targeted artifact destruction, read-only forensic analysis, advanced file carving (contiguous & fragmented), multi-level post-sanitization verification, tamper-evident hash-chained audit logging, and cryptographic attestation.

---

## Key Capabilities

1. **Storage-Aware Device Discovery & Classification:** Deep identification across NVMe, SATA SSD, HDD, and removable flash media, distinguishing physical vs logical constraints and recognizing host boot/system disks to prevent accidental destruction.
2. **Capability-Aware Sanitization Policy Engine:** Standard compliance policies (NIST SP 800-88 Rev 1, DoD 5220.22-M, IEEE 2883-2022) mapped to media-native primitives (NVMe Format / Sanitize, ATA Secure Erase, Overwrite, Crypto-scramble).
3. **Targeted Deletion & Remnant Elimination:** Controlled logical shredding combined with slack-space wiping and unallocated cluster zeroing without risking whole-disk integrity.
4. **Forensic Recovery & Deep File Carving:** Read-only evidence acquisition, filesystem metadata parsing (FAT12/16/32, exFAT, NTFS, Ext4), raw signature scanning, contiguous carving, and graph-based fragmented reconstruction for JPEG, PDF, ZIP, and documents.
5. **Multi-Level Verification (L1–L4):**
   - **L1 (Logical):** Filesystem metadata inspection.
   - **L2 (Host-Visible):** Raw sector/block scanning & entropy profiling.
   - **L3 (Device-Reported):** Controller log verification.
   - **L4 (Forensic Validation):** End-to-end execution of the VANISH recovery pipeline against sanitized media to verify unrecoverability.
6. **Tamper-Evident Audit & Cryptographic Attestation:** SHA-256 hash-chained event logs, digital signature support (Ed25519), and compliance certificate generation.
7. **Virtual Disk & Simulation Laboratory:** Complete simulation suite for testing without requiring physical destruction of storage devices.

---

## Repository Structure

```text
VANISH/
├── docs/                     # Specifications, architecture, & coordination protocols
│   ├── 00_MASTER_README.md
│   ├── 01_MASTER_ENGINEERING_SPEC.md
│   ├── 02_TECH_STACK.md
│   ├── 03_REPOSITORY_STRUCTURE.md
│   ├── 04_TEAM_SPLIT.md
│   ├── 05_AGENT_RULES.md
│   ├── 06_API_CONTRACTS.md
│   ├── 07_TEST_STRATEGY.md
│   ├── 08_PHYSICAL_LAB.md
│   ├── 09_DEMO_WORKFLOW.md
│   ├── 10_IMPLEMENTATION_ROADMAP.md
│   ├── 11_AGENT_BOOTSTRAP_PROMPT.md
│   ├── 12_ATTESTATION_SPEC.md
│   ├── 13_GITHUB_COORDINATION.md
│   └── WORK_STATUS.md
├── src/                      # Frontend UI (React + TypeScript + Tailwind CSS)
│   ├── app/                  # Application root & layouts
│   ├── components/           # Reusable UI widgets & visualizers
│   ├── hooks/                # Custom React hooks
│   ├── pages/                # Primary application views
│   ├── services/             # Tauri IPC & API clients
│   └── types/                # Shared TypeScript contracts & interfaces
├── src-tauri/                # Backend Systems Core (Rust)
│   ├── src/
│   │   ├── common/           # Shared domain models & contracts
│   │   ├── device/           # Discovery, identity, & capability analysis
│   │   ├── platform/         # OS storage abstraction (Linux, Windows, mock)
│   │   ├── policy/           # Sanitization rules & recommendation engine
│   │   ├── sanitization/     # Block erase, cryptographic erase, overwrite
│   │   ├── deletion/         # File shredding & slack space sanitization
│   │   ├── verification/     # Entropy, pattern sampling, forensic verification
│   │   ├── audit/            # Hash-chained event log & Ed25519 attestation
│   │   ├── reporting/        # Certificate & compliance report generator
│   │   └── forensic/         # Forensic imaging, carving, & reconstruction
├── tests/                    # Unit, integration, recovery, & safety test suites
├── test-data/                # Sample files & virtual disk fixtures
├── lab/                      # Environment scripts & live test configs
└── tools/                    # Benchmarking & verification CLI utilities
```

---

## Getting Started

### Prerequisites
- Node.js (v18+) & npm / pnpm
- Rust & Cargo (1.75+)
- Tauri CLI (`cargo install tauri-cli`)

### Frontend Development
```bash
npm install
npm run dev
```

### Full Desktop Application (Tauri)
```bash
npm run tauri dev
```

### Running Tests
```bash
cargo test --manifest-path src-tauri/Cargo.toml
npm test
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
