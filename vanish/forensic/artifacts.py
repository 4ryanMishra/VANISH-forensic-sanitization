"""
VANISH Forensic Artifact Model & Provenance
Defines data structures for recovered artifacts, evidential hashes,
validation status, and sector-level provenance.
"""

from dataclasses import dataclass, asdict, field
from typing import List, Tuple, Optional
import datetime


@dataclass
class RecoveredArtifact:
    artifact_id: str
    source_device: str
    detected_offset: int
    file_type: str  # "PDF", "JPEG", "PNG", "ZIP", etc.
    size_bytes: int
    sha256_hash: str
    confidence_score: float  # 0.0 to 1.0
    validation_status: str  # "Valid", "Corrupted", "Truncated", "Unverified"
    discovered_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    sector_ranges: List[Tuple[int, int]] = field(default_factory=list)
    entropy_score: float = 0.0
    header_magic: str = ""
    output_path: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)
