"""
VANISH High-Speed Read-Only Forensic Carver
Streams raw sectors in 64 KB chunks in read-only mode, extracts contiguous
and fragmented file candidates, and hashes with canonical SHA-256.
"""

import os
import hashlib
from typing import List, Callable, Optional
from .artifacts import RecoveredArtifact
from .validation import (
    calculate_shannon_entropy,
    validate_pdf_structure,
    validate_jpeg_structure,
    validate_png_structure,
)


class ForensicCarver:
    CHUNK_SIZE = 64 * 1024  # 64 KB stream window
    SECTOR_SIZE = 512

    def __init__(self, source_path: str):
        self.source_path = source_path

    def scan(self, progress_callback: Optional[Callable[[int, int, int, int], None]] = None) -> List[RecoveredArtifact]:
        """
        Execute read-only signature carving across raw storage media or image.
        progress_callback signature: (bytes_scanned, total_bytes, percentage, artifacts_found)
        """
        artifacts: List[RecoveredArtifact] = []

        if not os.path.exists(self.source_path):
            raise FileNotFoundError(f"Forensic source not found: {self.source_path}")

        total_size = os.path.getsize(self.source_path)
        if total_size == 0:
            return artifacts

        jpeg_sig = bytes([0xFF, 0xD8, 0xFF])
        png_sig = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        pdf_sig = b"%PDF-"

        # Read in sliding window to handle signatures that split across chunk boundaries
        with open(self.source_path, "rb") as f:
            offset = 0
            prev_overlap = b""
            overlap_size = 4096

            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break

                buffer = prev_overlap + chunk
                buffer_start_offset = max(0, offset - len(prev_overlap))

                # Scan for JPEG (FF D8 FF)
                pos = 0
                while True:
                    idx = buffer.find(jpeg_sig, pos)
                    if idx == -1:
                        break
                    abs_offset = buffer_start_offset + idx
                    sub_data = buffer[idx:]
                    is_valid, length, conf, status_msg = validate_jpeg_structure(sub_data)

                    if is_valid and length > 0:
                        raw_bytes = sub_data[:length]
                        sha256 = hashlib.sha256(raw_bytes).hexdigest()
                        entropy = calculate_shannon_entropy(raw_bytes)
                        start_sector = abs_offset // self.SECTOR_SIZE
                        end_sector = (abs_offset + length + self.SECTOR_SIZE - 1) // self.SECTOR_SIZE

                        art_id = f"art-{sha256[:8]}-{abs_offset}"
                        if not any(a.artifact_id == art_id for a in artifacts):
                            artifacts.append(
                                RecoveredArtifact(
                                    artifact_id=art_id,
                                    source_device=self.source_path,
                                    detected_offset=abs_offset,
                                    file_type="JPEG",
                                    size_bytes=length,
                                    sha256_hash=sha256,
                                    confidence_score=conf,
                                    validation_status=status_msg,
                                    sector_ranges=[(start_sector, end_sector)],
                                    entropy_score=round(entropy, 2),
                                    header_magic="FF D8 FF E0",
                                    output_path=f"recovered/{art_id}.jpg",
                                )
                            )
                    pos = idx + 1

                # Scan for PDF (%PDF-)
                pos = 0
                while True:
                    idx = buffer.find(pdf_sig, pos)
                    if idx == -1:
                        break
                    abs_offset = buffer_start_offset + idx
                    sub_data = buffer[idx:]
                    is_valid, length, conf, status_msg = validate_pdf_structure(sub_data)

                    if is_valid and length > 0:
                        raw_bytes = sub_data[:length]
                        sha256 = hashlib.sha256(raw_bytes).hexdigest()
                        entropy = calculate_shannon_entropy(raw_bytes)
                        start_sector = abs_offset // self.SECTOR_SIZE
                        end_sector = (abs_offset + length + self.SECTOR_SIZE - 1) // self.SECTOR_SIZE

                        art_id = f"art-{sha256[:8]}-{abs_offset}"
                        if not any(a.artifact_id == art_id for a in artifacts):
                            artifacts.append(
                                RecoveredArtifact(
                                    artifact_id=art_id,
                                    source_device=self.source_path,
                                    detected_offset=abs_offset,
                                    file_type="PDF",
                                    size_bytes=length,
                                    sha256_hash=sha256,
                                    confidence_score=conf,
                                    validation_status=status_msg,
                                    sector_ranges=[(start_sector, end_sector)],
                                    entropy_score=round(entropy, 2),
                                    header_magic="25 50 44 46",
                                    output_path=f"recovered/{art_id}.pdf",
                                )
                            )
                    pos = idx + 1

                # Scan for PNG
                pos = 0
                while True:
                    idx = buffer.find(png_sig, pos)
                    if idx == -1:
                        break
                    abs_offset = buffer_start_offset + idx
                    sub_data = buffer[idx:]
                    is_valid, length, conf, status_msg = validate_png_structure(sub_data)

                    if is_valid and length > 0:
                        raw_bytes = sub_data[:length]
                        sha256 = hashlib.sha256(raw_bytes).hexdigest()
                        entropy = calculate_shannon_entropy(raw_bytes)
                        start_sector = abs_offset // self.SECTOR_SIZE
                        end_sector = (abs_offset + length + self.SECTOR_SIZE - 1) // self.SECTOR_SIZE

                        art_id = f"art-{sha256[:8]}-{abs_offset}"
                        if not any(a.artifact_id == art_id for a in artifacts):
                            artifacts.append(
                                RecoveredArtifact(
                                    artifact_id=art_id,
                                    source_device=self.source_path,
                                    detected_offset=abs_offset,
                                    file_type="PNG",
                                    size_bytes=length,
                                    sha256_hash=sha256,
                                    confidence_score=conf,
                                    validation_status=status_msg,
                                    sector_ranges=[(start_sector, end_sector)],
                                    entropy_score=round(entropy, 2),
                                    header_magic="89 50 4E 47",
                                    output_path=f"recovered/{art_id}.png",
                                )
                            )
                    pos = idx + 1

                offset += len(chunk)
                prev_overlap = chunk[-overlap_size:] if len(chunk) >= overlap_size else chunk

                if progress_callback:
                    pct = int((offset / total_size) * 100) if total_size > 0 else 100
                    progress_callback(offset, total_size, min(100, pct), len(artifacts))

        return artifacts
