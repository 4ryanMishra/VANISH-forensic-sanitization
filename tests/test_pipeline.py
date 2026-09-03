"""
VANISH Comprehensive End-to-End Test Suite
Tests:
1. Device discovery & fail-closed protection for root OS drives
2. Read-only forensic carving on synthetic multi-pattern buffers
3. NIST SP 800-88 Clear sanitization & L4 forensic auto-carve verification
4. SQLite cryptographic hash chain integrity and tamper detection
"""

import os
import tempfile
import pytest
import hashlib

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


# ------------------------------------------------------------------------------
# 1. Device Safety & Protection Tests
# ------------------------------------------------------------------------------

def test_device_protection_root_drive():
    """Ensure devices with mountpoints '/', '/boot', or internal system disks are protected."""
    root_dev = DeviceInfo(
        path="/dev/nvme0n1",
        name="nvme0n1",
        model="Samsung SSD 980 (OS)",
        size_bytes=512 * 1024 * 1024 * 1024,
        is_protected=True,
        is_usb=False,
        mountpoint="/",
    )
    assert root_dev.is_protected is True

    # Attempting to sanitize root drive MUST raise PermissionError
    with pytest.raises(PermissionError) as excinfo:
        SanitizationExecutor.sanitize_device(root_dev)
    assert "PROTECTED" in str(excinfo.value)


def test_device_discovery_enumeration():
    """Verify device discovery returns valid list with non-empty attributes."""
    devices = DeviceDiscovery.list_devices()
    assert len(devices) >= 2
    # At least one device should be protected (OS)
    assert any(d.is_protected for d in devices)
    # At least one device should be available target (USB or lab target)
    assert any(not d.is_protected for d in devices)


# ------------------------------------------------------------------------------
# 2. Forensic Carving & Validation Tests
# ------------------------------------------------------------------------------

def test_shannon_entropy():
    """Test entropy calculation: 0.0 for uniform zeroes, ~8.0 for uniform random bytes."""
    zeros = b"\x00" * 1024
    assert calculate_shannon_entropy(zeros) == 0.0

    all_bytes = bytes(range(256))
    ent = calculate_shannon_entropy(all_bytes)
    assert abs(ent - 8.0) < 0.01


def test_forensic_carver_synthetic_buffer():
    """Test carver on synthetic 10 MB buffer containing noise + valid PDF + valid JPEG + noise."""
    total_size = 10 * 1024 * 1024  # 10 MB
    buf = bytearray(b"\x00" * total_size)

    # Embed sample PDF at offset 1 MB
    pdf_offset = 1024 * 1024
    pdf_payload = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \ntrailer\n<< /Root 1 0 R >>\nstartxref\n120\n%%EOF\n"
    buf[pdf_offset : pdf_offset + len(pdf_payload)] = pdf_payload

    # Embed sample JPEG at offset 4 MB
    jpeg_offset = 4 * 1024 * 1024
    jpeg_header = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00])
    jpeg_sof = bytes([0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x11, 0x00])
    jpeg_sos = bytes([0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00])
    jpeg_body = bytes([i % 256 for i in range(2048)])
    jpeg_eoi = bytes([0xFF, 0xD9])
    jpeg_payload = jpeg_header + jpeg_sof + jpeg_sos + jpeg_body + jpeg_eoi
    buf[jpeg_offset : jpeg_offset + len(jpeg_payload)] = jpeg_payload

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(buf)
        tmp_path = tmp.name

    try:
        carver = ForensicCarver(tmp_path)
        artifacts = carver.scan()

        assert len(artifacts) == 2
        pdf_art = next(a for a in artifacts if a.file_type == "PDF")
        jpeg_art = next(a for a in artifacts if a.file_type == "JPEG")

        assert pdf_art.detected_offset == pdf_offset
        assert pdf_art.sha256_hash == hashlib.sha256(pdf_payload).hexdigest()
        assert pdf_art.confidence_score >= 0.9

        assert jpeg_art.detected_offset == jpeg_offset
        assert jpeg_art.sha256_hash == hashlib.sha256(jpeg_payload).hexdigest()
        assert jpeg_art.confidence_score >= 0.9
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


# ------------------------------------------------------------------------------
# 3. Sanitization & Closed-Loop L4 Verification Tests
# ------------------------------------------------------------------------------

def test_zero_fill_sanitization_and_l4_verification():
    """Test full cycle: dirty disk -> sanitize with zero-fill -> L1, L2, L4 pass with 0 artifacts."""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        # Write initial dirty payload
        tmp.write(b"CONFIDENTIAL_DATA_RESTRICTED" * 1000)
        tmp.write(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\ntrailer\nstartxref\n50\n%%EOF\n")
        tmp.write(b"TRAILING_REMNANTS" * 500)
        tmp_path = tmp.name

    try:
        file_size = os.path.getsize(tmp_path)
        target_dev = DeviceInfo(
            path=tmp_path,
            name=os.path.basename(tmp_path),
            model="Synthetic Test Drive (1 MB)",
            size_bytes=file_size,
            is_protected=False,
            is_usb=True,
            mountpoint=None,
        )

        # 1. Pre-sanitization check: carver finds PDF
        pre_carver = ForensicCarver(tmp_path)
        pre_artifacts = pre_carver.scan()
        assert len(pre_artifacts) >= 1

        # 2. Execute NIST SP 800-88 Clear Sanitization
        summary = SanitizationExecutor.sanitize_device(target_dev)
        assert summary["success"] is True
        assert summary["passes_completed"] == 1

        # 3. Post-sanitization L1-L4 verification
        report = VerificationEngine.verify_sanitization(target_dev)
        assert report["overall_passed"] is True
        assert report["confidence_pct"] >= 80

        # Verify all L1, L2, L4 passed
        levels = {lvl["level"]: lvl for lvl in report["levels"]}
        assert levels["L1 Logical Filesystem"]["passed"] is True
        assert levels["L2 Host-Visible Blocks"]["passed"] is True
        assert levels["L4 Forensic Carving Handshake"]["passed"] is True
        assert levels["L4 Forensic Carving Handshake"]["artifacts_found"] == 0

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


# ------------------------------------------------------------------------------
# 4. Tamper-Evident Audit Chain Integrity Tests
# ------------------------------------------------------------------------------

def test_audit_chain_cryptographic_integrity():
    """Test SQLite audit chain append, verification, and tamper detection."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_audit.db")
        chain = AuditChain(db_path=db_path)

        # Append 3 distinct operations
        e1 = chain.append_event("DEVICE_DISCOVERY", "/dev/sdb", "SUCCESS", "Target enumerated")
        e2 = chain.append_event("FORENSIC_CARVE", "/dev/sdb", "SUCCESS", "Found 2 files")
        e3 = chain.append_event("SANITIZATION_NIST_CLEAR", "/dev/sdb", "SUCCESS", "Sanitized 16 GB")

        # Initial chain integrity check must pass
        is_valid, msg = chain.verify_chain_integrity()
        assert is_valid is True
        assert "100% cryptographic integrity" in msg

        # Tamper test: manually modify record #2 in SQLite database
        import sqlite3
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("UPDATE audit_events SET operation = 'TAMPERED_OPERATION' WHERE id = 2")
            conn.commit()
        finally:
            conn.close()

        # Chain verification must now FAIL-CLOSED
        is_valid, msg = chain.verify_chain_integrity()
        assert is_valid is False
        assert "tamper detected" in msg.lower()
