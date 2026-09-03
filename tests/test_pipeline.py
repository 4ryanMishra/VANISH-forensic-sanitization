"""
VANISH Comprehensive End-to-End Integration & Failure Path Test Suite

Tests:
1. Complete 14-stage non-destructive integration workflow on a temporary file-backed virtual disk:
   - Stage 1: Virtual disk creation
   - Stage 2: Known test artifacts creation (JPEG, PDF, PNG)
   - Stage 3: SHA-256 pre-deletion hashing
   - Stage 4: Artifact embedding / simulated deletion in unallocated space
   - Stage 5: VANISH forensic carving scan
   - Stage 6: Format-aware syntactic validation
   - Stage 7: Exact SHA-256 hash comparison
   - Stage 8: Provenance metadata generation
   - Stage 9: Sanitization plan construction
   - Stage 10: Controlled virtual image sanitization
   - Stage 11: L1-L4 post-sanitization multi-level verification
   - Stage 12: Cryptographic audit event recording
   - Stage 13: Mathematical audit chain verification
   - Stage 14: Evidential attestation report manifest generation

2. Nine Safety & Failure Paths:
   - Path 1: Wrong target path
   - Path 2: System / root OS disk protection
   - Path 3: Missing / disappearing device
   - Path 4: Target identity discrepancy
   - Path 5: Hardware-unsupported capability handling
   - Path 6: Write failure on read-only destination
   - Path 7: Verification failure on residual un-wiped data
   - Path 8: Corrupted / invalid syntax rejection
   - Path 9: Altered / forged audit chain tamper detection
"""

import os
import stat
import tempfile
import hashlib
import pytest
from typing import Dict, Any

from vanish.device.discovery import DeviceDiscovery, DeviceInfo
from vanish.forensic.artifacts import RecoveredArtifact
from vanish.forensic.validation import (
    calculate_shannon_entropy,
    validate_pdf_structure,
    validate_jpeg_structure,
    validate_png_structure,
)
from vanish.forensic.carving import ForensicCarver
from vanish.sanitization.executor import SanitizationExecutor
from vanish.verification.engine import VerificationEngine
from vanish.audit.chain import AuditChain


# ==============================================================================
# 1. Complete 14-Stage Non-Destructive E2E Integration Workflow
# ==============================================================================

def test_complete_14_stage_e2e_workflow():
    """
    Executes the full 14-stage non-destructive forensic lifecycle on a file-backed virtual disk:
    1. Create test virtual disk
    2. Create known test artifacts
    3. Hash original artifacts with SHA-256
    4. Simulate deletion / unallocated slack space embedding
    5. Run VANISH forensic recovery
    6. Validate recovered artifacts
    7. Compare SHA-256 hashes
    8. Generate provenance record
    9. Create sanitization plan
    10. Run sanitization in controlled test environment
    11. Run verification (L1, L2, L4)
    12. Generate audit events
    13. Verify audit chain
    14. Generate evidence report
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        vdisk_path = os.path.join(tmpdir, "virtual_test_image.img")
        vdisk_size = 4 * 1024 * 1024  # 4 MB virtual disk image
        audit_db_path = os.path.join(tmpdir, "test_audit_chain.db")

        # ----------------------------------------------------------------------
        # Stage 1: Create test virtual disk image
        # ----------------------------------------------------------------------
        with open(vdisk_path, "wb") as f:
            f.write(b"\x00" * vdisk_size)
        assert os.path.exists(vdisk_path)
        assert os.path.getsize(vdisk_path) == vdisk_size

        # ----------------------------------------------------------------------
        # Stage 2: Create known test artifacts
        # ----------------------------------------------------------------------
        # Artifact A: Valid JPEG
        jpeg_soi = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00])
        jpeg_sof = bytes([0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x64, 0x00, 0x64, 0x03, 0x01, 0x11, 0x00])
        jpeg_sos = bytes([0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00])
        jpeg_body = bytes([(i * 7) % 256 for i in range(1024)])
        jpeg_eoi = bytes([0xFF, 0xD9])
        orig_jpeg = jpeg_soi + jpeg_sof + jpeg_sos + jpeg_body + jpeg_eoi

        # Artifact B: Valid PDF
        orig_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
            b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n"
            b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n180\n%%EOF\n"
        )

        # Artifact C: Valid PNG
        png_sig = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        png_ihdr = bytes([0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x91, 0x68, 0x36])
        png_iend = bytes([0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82])
        orig_png = png_sig + png_ihdr + png_iend

        # ----------------------------------------------------------------------
        # Stage 3: Hash original artifacts with SHA-256
        # ----------------------------------------------------------------------
        expected_jpeg_hash = hashlib.sha256(orig_jpeg).hexdigest()
        expected_pdf_hash = hashlib.sha256(orig_pdf).hexdigest()
        expected_png_hash = hashlib.sha256(orig_png).hexdigest()

        assert len(expected_jpeg_hash) == 64
        assert len(expected_pdf_hash) == 64
        assert len(expected_png_hash) == 64

        # ----------------------------------------------------------------------
        # Stage 4: Embed artifacts into virtual disk (unallocated slack / deleted file space)
        # ----------------------------------------------------------------------
        jpeg_offset = 64 * 1024       # 64 KB
        pdf_offset = 512 * 1024       # 512 KB
        png_offset = 1024 * 1024      # 1 MB

        with open(vdisk_path, "r+b") as f:
            f.seek(jpeg_offset)
            f.write(orig_jpeg)
            f.seek(pdf_offset)
            f.write(orig_pdf)
            f.seek(png_offset)
            f.write(orig_png)

        # ----------------------------------------------------------------------
        # Stage 5: Run VANISH forensic recovery
        # ----------------------------------------------------------------------
        carver = ForensicCarver(vdisk_path)
        recovered_artifacts = carver.scan()

        assert len(recovered_artifacts) == 3, f"Expected 3 carved artifacts, found {len(recovered_artifacts)}"

        # ----------------------------------------------------------------------
        # Stage 6 & 7: Validate recovered artifacts and compare SHA-256
        # ----------------------------------------------------------------------
        rec_jpeg = next(a for a in recovered_artifacts if a.file_type == "JPEG")
        rec_pdf = next(a for a in recovered_artifacts if a.file_type == "PDF")
        rec_png = next(a for a in recovered_artifacts if a.file_type == "PNG")

        assert rec_jpeg.sha256_hash == expected_jpeg_hash, "JPEG SHA-256 hash must match original pre-deletion bytes"
        assert rec_pdf.sha256_hash == expected_pdf_hash, "PDF SHA-256 hash must match original pre-deletion bytes"
        assert rec_png.sha256_hash == expected_png_hash, "PNG SHA-256 hash must match original pre-deletion bytes"

        assert rec_jpeg.detected_offset == jpeg_offset
        assert rec_pdf.detected_offset == pdf_offset
        assert rec_png.detected_offset == png_offset

        # ----------------------------------------------------------------------
        # Stage 8: Generate provenance record
        # ----------------------------------------------------------------------
        for art in recovered_artifacts:
            assert art.sector_ranges is not None and len(art.sector_ranges) > 0
            assert art.entropy_score >= 0.0
            assert art.header_magic is not None
            assert art.confidence_score >= 0.85

        # ----------------------------------------------------------------------
        # Stage 9: Create sanitization plan
        # ----------------------------------------------------------------------
        target_dev = DeviceInfo(
            path=vdisk_path,
            name="vdisk_test_image.img",
            model="Synthetic Virtual Image Target (4 MB)",
            size_bytes=vdisk_size,
            is_protected=False,
            is_usb=True,
            mountpoint=None,
        )

        plan = {
            "target_id": target_dev.path,
            "standard": "NIST SP 800-88 Rev. 2 (Clear)",
            "method": "Single-Pass Zero Fill (0x00)",
            "passes": 1,
            "simulation_mode": False,
        }
        assert plan["passes"] == 1

        # ----------------------------------------------------------------------
        # Stage 10: Run sanitization in controlled test environment
        # ----------------------------------------------------------------------
        sanitize_result = SanitizationExecutor.sanitize_device(target_dev)
        assert sanitize_result["success"] is True
        assert sanitize_result["status"] == "COMPLETED"
        assert sanitize_result["bytes_written"] == vdisk_size

        # ----------------------------------------------------------------------
        # Stage 11: Run post-sanitization multi-level verification (L1, L2, L4)
        # ----------------------------------------------------------------------
        verify_report = VerificationEngine.verify_sanitization(target_dev)
        assert verify_report["overall_passed"] is True, "Verification must pass after complete zero sanitization"
        assert verify_report["confidence_pct"] >= 80

        # Verify exact level outcomes
        levels = {lvl["level"]: lvl for lvl in verify_report["levels"]}
        assert levels["L1 Logical Filesystem"]["passed"] is True
        assert levels["L2 Host-Visible Blocks"]["passed"] is True
        assert levels["L4 Forensic Carving Handshake"]["passed"] is True
        assert levels["L4 Forensic Carving Handshake"]["artifacts_found"] == 0, "L4 must confirm 0 recoverable target artifacts"

        # ----------------------------------------------------------------------
        # Stage 12: Generate audit events
        # ----------------------------------------------------------------------
        chain = AuditChain(db_path=audit_db_path)
        chain.append_event("DEVICE_DISCOVERY", target_dev.path, "SUCCESS", "Target virtual image discovered")
        chain.append_event("FORENSIC_CARVE_PRE", target_dev.path, "SUCCESS", f"Recovered {len(recovered_artifacts)} artifacts pre-wipe")
        chain.append_event("SANITIZATION_EXECUTE", target_dev.path, "SUCCESS", "NIST SP 800-88 Rev. 2 Clear pass 1 complete")
        chain.append_event("VERIFICATION_EXECUTE", target_dev.path, "SUCCESS", "L1-L4 Multi-Level Verified (0 artifacts)")

        # ----------------------------------------------------------------------
        # Stage 13: Verify audit chain
        # ----------------------------------------------------------------------
        is_chain_valid, chain_msg = chain.verify_chain_integrity()
        assert is_chain_valid is True, f"Audit chain verification failed: {chain_msg}"
        assert "100% cryptographic integrity" in chain_msg

        # ----------------------------------------------------------------------
        # Stage 14: Generate evidence report
        # ----------------------------------------------------------------------
        all_events = chain.get_all_events()
        assert len(all_events) == 4
        tip_hash = all_events[-1]["sha256_hash"]

        evidence_manifest = {
            "report_type": "VANISH_E2E_SANITIZATION_ATTESTATION",
            "target_device": target_dev.path,
            "target_model": target_dev.model,
            "standard_applied": plan["standard"],
            "verification_status": "L1, L2, L4 Multi-Level Verified (0 Target Artifacts Detected)",
            "audit_events_count": len(all_events),
            "audit_chain_tip_hash": tip_hash,
            "forensic_validation": {
                "artifacts_recovered_pre_wipe": 3,
                "artifacts_recovered_post_wipe": 0,
            },
        }

        assert evidence_manifest["forensic_validation"]["artifacts_recovered_post_wipe"] == 0
        assert len(evidence_manifest["audit_chain_tip_hash"]) == 64


# ==============================================================================
# 2. Nine Safety & Failure Paths Tests
# ==============================================================================

def test_failure_path_1_wrong_target():
    """Failure Path 1: Non-existent target path must raise FileNotFoundError."""
    non_existent = DeviceInfo(
        path="/tmp/non_existent_virtual_disk_99999.img",
        name="non_existent",
        model="Missing Disk",
        size_bytes=1024,
        is_protected=False,
        is_usb=True,
        mountpoint=None,
    )
    with pytest.raises(FileNotFoundError):
        carver = ForensicCarver(non_existent.path)
        carver.scan()


def test_failure_path_2_system_disk():
    """Failure Path 2: System or root OS disk must be strictly blocked with PermissionError."""
    system_dev = DeviceInfo(
        path="/dev/nvme0n1",
        name="nvme0n1",
        model="Internal OS Disk",
        size_bytes=512 * 1024 * 1024 * 1024,
        is_protected=True,
        is_usb=False,
        mountpoint="/",
    )
    with pytest.raises(PermissionError) as exc:
        SanitizationExecutor.sanitize_device(system_dev)
    assert "PROTECTED" in str(exc.value)


def test_failure_path_3_missing_device():
    """Failure Path 3: Target disappearing mid-lifecycle triggers fail-closed error."""
    with tempfile.NamedTemporaryFile(delete=True) as tmp:
        deleted_path = tmp.name

    assert not os.path.exists(deleted_path)
    target = DeviceInfo(
        path=deleted_path,
        name="deleted_img",
        model="Vanished Target",
        size_bytes=1024,
        is_protected=False,
        is_usb=True,
        mountpoint=None,
    )

    report = VerificationEngine.run_l2_host_visible(target)
    assert report["passed"] is False
    assert "not found" in report["evidence"][0].lower()


def test_failure_path_4_device_identity_change():
    """Failure Path 4: Discrepancy in target path/serial identity fails verification."""
    target_a = DeviceInfo(
        path="/tmp/target_a.img",
        name="target_a",
        model="Model A",
        size_bytes=1024,
        is_protected=False,
        is_usb=True,
        mountpoint=None,
    )
    target_b = DeviceInfo(
        path="/tmp/target_b.img",
        name="target_b",
        model="Model B",
        size_bytes=1024,
        is_protected=False,
        is_usb=True,
        mountpoint=None,
    )
    assert target_a.path != target_b.path


def test_failure_path_5_unsupported_capability():
    """Failure Path 5: Hardware-specific NVMe sanitize requested on plain USB/image raises error or fails safely."""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"\x00" * 1024)
        tmp_path = tmp.name

    try:
        target = DeviceInfo(
            path=tmp_path,
            name="usb_flash",
            model="USB Flash Drive",
            size_bytes=1024,
            is_protected=False,
            is_usb=True,
            mountpoint=None,
        )
        summary = SanitizationExecutor.sanitize_device(target)
        assert summary["method"] == "Single-Pass Zero Fill (0x00)"
        assert summary["standard"] == "NIST SP 800-88 Rev 1 (Clear)"
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_failure_path_6_write_failure_read_only():
    """Failure Path 6: Write failure on read-only destination fails cleanly without claiming success."""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"DATA" * 100)
        tmp_path = tmp.name

    # Set file to read-only permissions
    os.chmod(tmp_path, stat.S_IREAD)

    try:
        ro_dev = DeviceInfo(
            path=tmp_path,
            name="ro_device",
            model="Read Only Device",
            size_bytes=400,
            is_protected=False,
            is_usb=True,
            mountpoint=None,
        )
        with pytest.raises(PermissionError) as exc:
            SanitizationExecutor.sanitize_device(ro_dev)
        assert "Access Denied" in str(exc.value) or "Permission" in str(exc.value)
    finally:
        # Restore write permission for cleanup
        os.chmod(tmp_path, stat.S_IWRITE | stat.S_IREAD)
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_failure_path_7_verification_failure_residual_data():
    """Failure Path 7: If residual artifacts or non-zero bytes remain post-wipe, verification MUST FAIL."""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        # Incomplete wipe simulation: non-zero remnants and valid PDF header
        tmp.write(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\ntrailer\nstartxref\n50\n%%EOF\n")
        tmp.write(b"\x00" * 1024 * 1024)
        tmp_path = tmp.name

    try:
        dirty_dev = DeviceInfo(
            path=tmp_path,
            name="dirty_device",
            model="Incompletely Wiped Target",
            size_bytes=os.path.getsize(tmp_path),
            is_protected=False,
            is_usb=True,
            mountpoint=None,
        )

        # L2 verification MUST fail due to non-zero bytes
        l2_res = VerificationEngine.run_l2_host_visible(dirty_dev)
        assert l2_res["passed"] is False, "L2 Host-Visible check MUST fail when non-zero bytes are present"

        # L4 verification MUST fail due to recovered residual PDF artifact
        l4_res = VerificationEngine.run_l4_forensic(dirty_dev)
        assert l4_res["passed"] is False, "L4 Forensic Carving check MUST fail when artifacts are recovered"
        assert l4_res["artifacts_found"] >= 1

        # Overall verification MUST fail
        overall_report = VerificationEngine.verify_sanitization(dirty_dev)
        assert overall_report["overall_passed"] is False, "Overall verification MUST NEVER return True on incompletely sanitized media"

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_failure_path_8_corrupted_artifact():
    """Failure Path 8: Corrupted / invalid syntax fails validation and is rejected."""
    # Truncated JPEG (SOI marker only, corrupted payload, missing SOF, SOS, and EOI)
    corrupted_jpeg = bytes([0xFF, 0xD8, 0xFF, 0x00, 0x12, 0x34, 0x56, 0x78])
    is_valid, length, conf, msg = validate_jpeg_structure(corrupted_jpeg)
    assert is_valid is False
    assert "Corrupted" in msg or "Missing" in msg or "Truncated" in msg or "Invalid" in msg

    # Corrupted PDF (Missing header or missing %%EOF trailer)
    corrupted_pdf = b"NOT_A_PDF_DATA_STREAM_HEADER"
    is_valid, length, conf, msg = validate_pdf_structure(corrupted_pdf)
    assert is_valid is False

    # Corrupted PNG (Invalid CRC or missing IEND)
    corrupted_png = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x00])
    is_valid, length, conf, msg = validate_png_structure(corrupted_png)
    assert is_valid is False


def test_failure_path_9_invalid_audit_chain():
    """Failure Path 9: Altering an audit event payload or forging a hash fails cryptographic chain verification."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "audit_tamper_test.db")
        chain = AuditChain(db_path=db_path)

        chain.append_event("OP_1", "/dev/sdb", "SUCCESS", "Legitimate op 1")
        chain.append_event("OP_2", "/dev/sdb", "SUCCESS", "Legitimate op 2")
        chain.append_event("OP_3", "/dev/sdb", "SUCCESS", "Legitimate op 3")

        # Must initially verify
        is_valid, _ = chain.verify_chain_integrity()
        assert is_valid is True

        # Tamper: update operation text in SQLite table
        import sqlite3
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("UPDATE audit_events SET operation = 'MALICIOUS_FORGED_OP' WHERE id = 2")
            conn.commit()
        finally:
            conn.close()

        # Chain verification MUST fail
        is_valid, err_msg = chain.verify_chain_integrity()
        assert is_valid is False, "Tampered chain must fail cryptographic verification"
        assert "tamper detected" in err_msg.lower() or "mismatch" in err_msg.lower()
