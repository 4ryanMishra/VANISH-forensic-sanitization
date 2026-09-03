#!/usr/bin/env python3
"""
VANISH - One-Click Presentation & Judge Demo Launcher (SIH 2026 / NTRO PS 26149)
Automates pre-flight diagnostics, administrative privilege checks,
dependency verification, and launches the PySide6 Workstation in presentation mode.
"""

import sys
import os
import platform
import subprocess

# Ensure repo root is in python path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT_DIR)


def check_privileges():
    """Verify administrator or root privileges for physical raw disk I/O."""
    is_admin = False
    system = platform.system().lower()

    if system == "windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
    else:
        is_admin = os.geteuid() == 0

    return is_admin


def run_preflight_diagnostics():
    print("=================================================================")
    print("  VANISH - PRE-FLIGHT PRESENTATION DIAGNOSTICS (SIH 2026)")
    print("=================================================================")

    # 1. Dependency checks
    try:
        import PySide6
        print(f"[+] GUI Framework: PySide6 v{PySide6.__version__} [INSTALLED]")
    except ImportError:
        print("[!] PySide6 missing. Installing via pip...")
        subprocess.run([sys.executable, "-m", "pip", "install", "PySide6"], check=True)

    try:
        import pytest
        print(f"[+] Verification Engine: pytest v{pytest.__version__} [INSTALLED]")
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "pytest"], check=True)

    # 2. Check privileges
    has_admin = check_privileges()
    if has_admin:
        print("[+] Process Privileges: ELEVATED (Raw Controller Access Enabled) [OK]")
    else:
        print("[*] Process Privileges: STANDARD USER (Virtual Lab & Partition Mode Active)")

    # 3. Check / Regenerate Lab Test Disk
    lab_img = os.path.join(ROOT_DIR, "test-data", "virtual-disks", "vanish_lab_image.img")
    if not os.path.exists(lab_img) or os.path.getsize(lab_img) < 1024 * 1024:
        print("[*] Initializing synthetic test image for instant demo carving...")
        from tools.generate_virtual_disk import generate_virtual_disk
        generate_virtual_disk(lab_img)
    print(f"[+] Lab Disk Image: {lab_img} [READY]")

    # 4. Device Discovery Check
    from vanish.device.discovery import DeviceDiscovery
    devices = DeviceDiscovery.list_devices()
    print(f"[+] Storage Bus Discovery: {len(devices)} storage targets detected:")
    for d in devices:
        badge = "[PROTECTED OS]" if d.is_protected else "[READY TARGET]"
        print(f"    * {d.name} ({d.model}) - {d.size_gb} GB {badge}")

    print("\n=================================================================")
    print("  LAUNCHING VANISH DESKTOP WORKSTATION...")
    print("=================================================================\n")


def launch_presentation():
    run_preflight_diagnostics()

    from PySide6.QtWidgets import QApplication
    from vanish.ui.app import VanishMainWindow

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("VANISH Forensics & Sanitization Workstation")

    window = VanishMainWindow()
    window.showMaximized()
    sys.exit(app.exec())


if __name__ == "__main__":
    launch_presentation()
