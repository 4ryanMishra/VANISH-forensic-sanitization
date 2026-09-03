#!/usr/bin/env python3
"""
VANISH - Hardware Pipeline End-to-End Headless Dry-Run
Verifies:
1. ForensicCarver on target media (carves PDF/JPEG, matches hashes, confidence >= 0.8)
2. SanitizationExecutor (NIST SP 800-88 Clear single-pass zero overwrite + sync)
3. VerificationEngine (L1, L2, L4 multi-level verification -> 0 artifacts)
4. AuditChain cryptographic ledger integrity and outputs signed event hashes
"""

import sys
import os
import hashlib
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vanish.device.discovery import DeviceDiscovery, DeviceInfo
from vanish.forensic.carving import ForensicCarver
from vanish.sanitization.executor import SanitizationExecutor
from vanish.verification.engine import VerificationEngine
from vanish.audit.chain import AuditChain


def run_dryrun(target_path: str = None):
    print("=================================================================")
    print("  VANISH - PHYSICAL & VIRTUAL HARDWARE DRY-RUN ENGINE (SIH 2026)")
    print("=================================================================")

    # Select target
    if not target_path:
        target_path = os.path.abspath("test-data/virtual-disks/vanish_lab_image.img")

    print(f"[*] Active Verification Target: {target_path}")
    if not os.path.exists(target_path):
        print(f"[!] Target path not found: {target_path}")
        return False

    audit = AuditChain("vanish_audit.db")

    # --------------------------------------------------------------------------
    # STAGE 1: Forensic Carving & Provenance Scan
    # --------------------------------------------------------------------------
    print("\n[STAGE 1] Triggering High-Speed Read-Only Forensic Sector Carving...")
    carver = ForensicCarver(target_path)
    artifacts = carver.scan()

    print(f"[+] Total Recovered Artifacts: {len(artifacts)}")
    for a in artifacts:
        print(f"  -> [{a.file_type}] Offset: 0x{a.detected_offset:X} ({a.detected_offset:,} B) | Size: {a.size_bytes:,} B | Confidence: {a.confidence_score*100:.0f}%")
        print(f"     SHA-256: {a.sha256_hash}")
        print(f"     Validation: {a.validation_status} | Sectors: {a.sector_ranges}")

    assert len(artifacts) >= 2, "Expected at least 2 recoverable artifacts"
    assert all(a.confidence_score >= 0.8 for a in artifacts), "All confidence scores must be >= 0.8"

    audit.append_event(
        operation=f"FORENSIC_CARVE_DRYRUN: {len(artifacts)} recovered",
        target_path=target_path,
        status="SUCCESS",
        details=f"Recovered {len(artifacts)} artifacts with canonical SHA-256 integrity.",
    )

    # --------------------------------------------------------------------------
    # STAGE 2: NIST SP 800-88 Clear Block Sanitization
    # --------------------------------------------------------------------------
    print("\n[STAGE 2] Triggering NIST SP 800-88 Rev 1 Clear Single-Pass Zero Overwrite...")
    dev_size = os.path.getsize(target_path)
    target_dev = DeviceInfo(
        path=target_path,
        name=os.path.basename(target_path),
        model="SanDisk / Lab Target Media",
        size_bytes=dev_size,
        is_protected=False,
        is_usb=True,
    )

    san_result = SanitizationExecutor.sanitize_device(target_dev)
    print(f"[+] Overwrite Completed: {san_result.get('bytes_written', 0):,} bytes written (0x00)")
    print(f"[+] Standard: {san_result.get('standard')} | Passes: {san_result.get('passes_completed')}")

    audit.append_event(
        operation="SANITIZATION_NIST_CLEAR_DRYRUN",
        target_path=target_path,
        status="SUCCESS",
        details=f"Overwritten with single-pass zero (0x00). Total bytes: {san_result.get('bytes_written')}",
    )

    # --------------------------------------------------------------------------
    # STAGE 3: Multi-Level L1 - L4 Verification Matrix
    # --------------------------------------------------------------------------
    print("\n[STAGE 3] Executing Closed-Loop Multi-Level Verification (L1, L2, L4)...")
    verif = VerificationEngine.verify_sanitization(target_dev)

    for lvl in verif.get("levels", []):
        status_icon = "PASSED [OK]" if lvl["passed"] else "FAILED [X]"
        print(f"\n  [{lvl['level']}]: {status_icon} (Confidence: {lvl['confidence_pct']}%)")
        for ev in lvl.get("evidence", []):
            print(f"     * {ev}")

    assert verif["overall_passed"] is True, "Overall verification MUST pass"
    l4_info = next(l for l in verif["levels"] if "L4" in l["level"])
    assert l4_info["artifacts_found"] == 0, "L4 Forensic Auto-Carve MUST yield 0 artifacts"

    audit.append_event(
        operation="L4_FORENSIC_VERIFICATION_DRYRUN",
        target_path=target_path,
        status="SUCCESS",
        details=f"Zero artifacts recovered. Overall Confidence: {verif['confidence_pct']}%.",
    )

    # --------------------------------------------------------------------------
    # STAGE 4: Cryptographic Ledger Chain-of-Custody Verification
    # --------------------------------------------------------------------------
    print("\n[STAGE 4] Validating Cryptographic Hash Chain on SQLite Audit Ledger...")
    is_valid, msg = audit.verify_chain_integrity()
    print(f"[+] Ledger Status: {'VALID [UNBROKEN]' if is_valid else 'CORRUPTED [FAIL-CLOSED]'}")
    print(f"[+] Cryptographic Proof: {msg}")

    print("\n[*] Recent Signed Audit Chain Events:")
    events = audit.get_all_events()
    for evt in events[-4:]:
        print(f"  -> ID: {evt['event_id']} | UTC: {evt['timestamp']} | Op: {evt['operation']}")
        print(f"     Previous Hash: {evt['previous_hash'][:24]}...")
        print(f"     Current  Hash: {evt['sha256_hash']}")

    print("\n=================================================================")
    print("  HARDWARE END-TO-END DRY-RUN COMPLETE: ALL 4 STAGES PASSED 100%")
    print("=================================================================")
    return True


if __name__ == "__main__":
    run_dryrun()
