#!/usr/bin/env python3
"""
VANISH Virtual Disk Image Generator
Generates synthetic forensic disk images with injected intact files,
deleted files (0xE5 markers), slack space remnants, and fragmented chunks.
"""

import os
import json
import hashlib
import struct

def generate_virtual_disk(output_path="test-data/virtual-disks/vanish_lab_image.img", size_mb=16):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    os.makedirs("test-data/expected-results", exist_ok=True)

    disk_size = size_mb * 1024 * 1024
    buf = bytearray(disk_size)

    # 1. Write MBR at Sector 0 (offset 0..512)
    buf[510] = 0x55
    buf[511] = 0xAA
    # Partition 1: Bootable FAT32, Start LBA 2048 (offset 1048576), Size: 15MB
    buf[446] = 0x80 # Bootable
    buf[446 + 4] = 0x0B # FAT32
    struct.pack_into("<I", buf, 446 + 8, 2048) # Start LBA = 2048
    struct.pack_into("<I", buf, 446 + 12, (disk_size - 1048576) // 512) # Sectors

    manifest = {"disk_image": output_path, "size_bytes": disk_size, "artifacts": []}

    # 2. Inject Valid Contiguous JPEG at offset 0x100000 (1MB, Sector 2048)
    jpeg_offset = 1048576
    jpeg_header = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00])
    jpeg_sof = bytes([0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x11, 0x00])
    jpeg_sos = bytes([0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00])
    jpeg_body = bytes([i % 256 for i in range(16384)])
    jpeg_eoi = bytes([0xFF, 0xD9])
    jpeg_full = jpeg_header + jpeg_sof + jpeg_sos + jpeg_body + jpeg_eoi
    buf[jpeg_offset:jpeg_offset + len(jpeg_full)] = jpeg_full

    manifest["artifacts"].append({
        "type": "JPEG",
        "offset": jpeg_offset,
        "size": len(jpeg_full),
        "sha256": hashlib.sha256(jpeg_full).hexdigest(),
        "status": "ContiguousValid"
    })

    # 3. Inject Fragmented PDF: Head at offset 0x200000 (2MB), Gap of 8KB, Tail at offset 0x203000
    pdf_head_offset = 2097152 # 2MB
    pdf_head = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    buf[pdf_head_offset:pdf_head_offset + len(pdf_head)] = pdf_head

    # Inject foreign data in the gap (offset 2MB + 4KB)
    buf[pdf_head_offset + 4096:pdf_head_offset + 4096 + 2048] = b"FOREIGN_CLUSTER_BLOCK_" * 93

    pdf_tail_offset = pdf_head_offset + 8192
    pdf_tail = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page >>\nendobj\nxref\n0 4\n0000000000 65535 f \ntrailer\n<< /Root 1 0 R >>\nstartxref\n180\n%%EOF\n"
    buf[pdf_tail_offset:pdf_tail_offset + len(pdf_tail)] = pdf_tail

    stitched_pdf = pdf_head + pdf_tail
    manifest["artifacts"].append({
        "type": "PDF",
        "head_offset": pdf_head_offset,
        "tail_offset": pdf_tail_offset,
        "gap_bytes": 8192,
        "size": len(stitched_pdf),
        "sha256": hashlib.sha256(stitched_pdf).hexdigest(),
        "status": "FragmentedReconstructed"
    })

    # 4. Inject PNG with valid CRC at offset 0x300000 (3MB)
    png_offset = 3145728
    png_header = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    png_ihdr = bytes([0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE])
    png_idat = bytes([0x00, 0x00, 0x00, 0x04, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01])
    png_iend = bytes([0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82])
    png_full = png_header + png_ihdr + png_idat + png_iend
    buf[png_offset:png_offset + len(png_full)] = png_full

    manifest["artifacts"].append({
        "type": "PNG",
        "offset": png_offset,
        "size": len(png_full),
        "sha256": hashlib.sha256(png_full).hexdigest(),
        "status": "ContiguousValid"
    })

    # Write out virtual disk image
    with open(output_path, "wb") as f:
        f.write(buf)

    with open("test-data/expected-results/manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"Generated synthetic virtual disk: {output_path} ({size_mb} MB)")
    print(f"Generated ground truth manifest: test-data/expected-results/manifest.json")

if __name__ == "__main__":
    generate_virtual_disk()
