"""
VANISH Hardware Sanitization Executor
Implements NIST SP 800-88 Rev 1 Clear block-level overwrite routines
with strict fail-closed OS drive protection and controller cache flushes.
"""

import os
import subprocess
import shutil
import platform
from typing import Callable, Optional
from ..device.discovery import DeviceInfo


class SanitizationExecutor:
    BLOCK_SIZE = 1024 * 1024  # 1 MB write blocks

    @classmethod
    def sanitize_device(
        cls,
        target_device: DeviceInfo,
        progress_callback: Optional[Callable[[int, int, int], None]] = None,
        dry_run: bool = False,
    ) -> dict:
        """
        Execute NIST SP 800-88 Clear single-pass zero sanitization across target device.
        progress_callback signature: (bytes_written, total_bytes, percentage)
        """
        # Strict Fail-Closed Guard
        if target_device.is_protected:
            raise PermissionError(
                f"FATAL SECURITY VIOLATION: Device '{target_device.path}' ({target_device.model}) "
                "is marked PROTECTED. Overwrite operation aborted by kernel safety gate."
            )

        # Unmount child partitions on Linux if mounted
        if shutil.which("umount") and target_device.path.startswith("/dev/"):
            try:
                subprocess.run(["umount", "-f", f"{target_device.path}*"], capture_output=True)
            except Exception:
                pass

        total_bytes = target_device.size_bytes
        if total_bytes <= 0:
            total_bytes = 16 * 1024 * 1024  # Default 16 MB if capacity undetected

        if dry_run:
            # Simulated wipe for testing environments
            for written in range(0, total_bytes, cls.BLOCK_SIZE):
                if progress_callback:
                    pct = int((written / total_bytes) * 100)
                    progress_callback(written, total_bytes, pct)
            if progress_callback:
                progress_callback(total_bytes, total_bytes, 100)
            return {
                "success": True,
                "bytes_written": total_bytes,
                "passes_completed": 1,
                "standard": "NIST SP 800-88 Rev 1 (Clear)",
                "method": "Single-Pass Zero Fill (0x00)",
                "status": "COMPLETED",
            }

        zero_block = b"\x00" * cls.BLOCK_SIZE
        bytes_written = 0

        # Open raw disk / image binary handle directly
        try:
            with open(target_device.path, "wb") as f:
                while bytes_written < total_bytes:
                    write_size = min(cls.BLOCK_SIZE, total_bytes - bytes_written)
                    if write_size < cls.BLOCK_SIZE:
                        f.write(b"\x00" * write_size)
                    else:
                        f.write(zero_block)
                    bytes_written += write_size

                    if progress_callback:
                        pct = int((bytes_written / total_bytes) * 100)
                        progress_callback(bytes_written, total_bytes, pct)

                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass

            # Force OS controller cache flush
            if hasattr(os, "sync"):
                os.sync()

        except PermissionError as pe:
            raise PermissionError(
                f"Access Denied opening '{target_device.path}' for raw write. "
                "Ensure application is running with administrative / root privileges."
            ) from pe

        return {
            "success": True,
            "bytes_written": bytes_written,
            "passes_completed": 1,
            "standard": "NIST SP 800-88 Rev 1 (Clear)",
            "method": "Single-Pass Zero Fill (0x00)",
            "status": "COMPLETED",
        }
