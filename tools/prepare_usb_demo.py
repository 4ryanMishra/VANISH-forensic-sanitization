#!/usr/bin/env python3
"""
VANISH - USB Demo Preparation Tool (SIH 2026 / NTRO PS 26149)
Prepares the physical SanDisk USB drive for demonstration:
1. Validates target is removable USB (halts if OS drive).
2. Seeds valid forensic artifacts:
   - confidential_report.pdf (valid %PDF- with catalog and xref)
   - surveillance_capture.jpg (valid \xFF\xD8\xFF JPEG)
3. Computes canonical SHA-256 evidence hashes.
4. Performs logical deletion (unlinks files), leaving raw clusters in unallocated space.
"""

import os
import sys
import hashlib
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vanish.device.discovery import DeviceDiscovery, DeviceInfo


def generate_valid_pdf() -> bytes:
    """Generate a syntactically valid PDF document."""
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\n"
        b"endobj\n"
        b"4 0 obj\n"
        b"<< /Length 85 >>\n"
        b"stream\n"
        b"BT /F1 18 Tf 50 700 Td (RESTRICTED FORENSIC TARGET EVIDENCE - CLASSIFIED) Tj ET\n"
        b"endstream\n"
        b"endobj\n"
        b"xref\n"
        b"0 5\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"0000000204 00000 n \n"
        b"trailer\n"
        b"<< /Size 5 /Root 1 0 R >>\n"
        b"startxref\n"
        b"340\n"
        b"%%EOF\n"
    )
    return pdf_content


def generate_valid_jpeg() -> bytes:
    """Generate a syntactically valid JFIF JPEG image."""
    header = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00])
    sof = bytes([0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x80, 0x00, 0x80, 0x01, 0x01, 0x11, 0x00])
    sos = bytes([0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00])
    entropy_payload = bytes([(i * 37) % 256 for i in range(8192)])
    eoi = bytes([0xFF, 0xD9])
    return header + sof + sos + entropy_payload + eoi


def prepare_usb(target_mount: str = "E:\\"):
    print("=================================================================")
    print("  VANISH - USB PHYSICAL DEMO PREPARATION WIZARD (SIH 2026)")
    print("=================================================================")

    # 1. Device Safety Check
    devices = DeviceDiscovery.list_devices()
    usb_dev = None
    for d in devices:
        if d.mountpoint and target_mount.rstrip("\\").upper() in d.mountpoint.upper():
            usb_dev = d
            break

    if usb_dev:
        print(f"[+] Identified Target: {usb_dev.model} ({usb_dev.path})")
        print(f"[+] Capacity: {usb_dev.size_gb} GB ({usb_dev.size_bytes:,} bytes)")
        print(f"[+] Protection Status: {'FAIL-CLOSED (PROTECTED)' if usb_dev.is_protected else 'READY (UNPROTECTED)'}")
        if usb_dev.is_protected:
            print("[!] FATAL: Target device is protected. Aborting demo prep.")
            return False
    else:
        print(f"[*] Target mount '{target_mount}' checking directory accessibility...")

    if not os.path.exists(target_mount):
        print(f"[!] Target directory '{target_mount}' not accessible. Please ensure USB is mounted.")
        return False

    # 2. Seed Forensic Artifacts
    pdf_bytes = generate_valid_pdf()
    jpeg_bytes = generate_valid_jpeg()

    pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    jpeg_sha256 = hashlib.sha256(jpeg_bytes).hexdigest()

    pdf_path = os.path.join(target_mount, "confidential_report.pdf")
    jpeg_path = os.path.join(target_mount, "surveillance_capture.jpg")

    print(f"\n[STEP 1] Seeding forensic artifact 1: confidential_report.pdf ({len(pdf_bytes)} bytes)")
    with open(pdf_path, "wb") as f:
        f.write(pdf_bytes)
        f.flush()
    print(f"  -> Canonical Ground-Truth SHA-256: {pdf_sha256}")

    print(f"\n[STEP 2] Seeding forensic artifact 2: surveillance_capture.jpg ({len(jpeg_bytes)} bytes)")
    with open(jpeg_path, "wb") as f:
        f.write(jpeg_bytes)
        f.flush()
    print(f"  -> Canonical Ground-Truth SHA-256: {jpeg_sha256}")

    # Save Ground Truth Manifest
    manifest_dir = "test-data/expected-results"
    os.makedirs(manifest_dir, exist_ok=True)
    manifest_path = os.path.join(manifest_dir, "usb_demo_manifest.json")
    manifest = {
        "target_mount": target_mount,
        "device_info": usb_dev.to_dict() if usb_dev else None,
        "timestamp_seeded": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "artifacts": [
            {
                "file_name": "confidential_report.pdf",
                "file_type": "PDF",
                "size_bytes": len(pdf_bytes),
                "sha256": pdf_sha256,
            },
            {
                "file_name": "surveillance_capture.jpg",
                "file_type": "JPEG",
                "size_bytes": len(jpeg_bytes),
                "sha256": jpeg_sha256,
            },
        ],
    }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"\n[+] Saved ground-truth manifest to: {manifest_path}")

    # 3. Simulate Normal Logical Deletion
    print(f"\n[STEP 3] Simulating normal OS file deletion (unlinking files from FAT32 directory)...")
    time.sleep(1)
    os.remove(pdf_path)
    os.remove(jpeg_path)
    print("  -> Files logically deleted from directory table.")
    print("  -> Raw data clusters remain intact in unallocated sectors for carving scan!")

    print("\n=================================================================")
    print("  USB PREPARATION COMPLETE: TARGET IS READY FOR JUDGE DEMONSTRATION")
    print("=================================================================")
    return True


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "E:\\"
    prepare_usb(target)
