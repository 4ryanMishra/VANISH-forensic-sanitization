"""
VANISH Hardware Device Discovery & Protection Layer
Performs read-only device discovery using lsblk (Linux) or Get-Disk (Windows)
with strict fail-closed protection for host OS drives, boot partitions, and root filesystems.
"""

from dataclasses import dataclass, asdict
from typing import List, Optional
import json
import subprocess
import shutil
import platform
import os


@dataclass
class DeviceInfo:
    path: str
    name: str
    model: str
    size_bytes: int
    is_protected: bool
    is_usb: bool
    mountpoint: Optional[str] = None
    vendor: str = ""
    serial: str = ""
    tran: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def size_gb(self) -> float:
        return round(self.size_bytes / (1024 ** 3), 2)

    @property
    def size_mb(self) -> float:
        return round(self.size_bytes / (1024 ** 2), 2)


class DeviceDiscovery:
    PROTECTED_MOUNTPOINTS = {"/", "/boot", "/boot/efi", "/home", "/etc", "/var", "/usr", "C:", "C:\\"}

    @classmethod
    def list_devices(cls) -> List[DeviceInfo]:
        """
        Enumerate physical and virtual storage devices.
        Uses lsblk on Linux and PowerShell Get-Disk on Windows with strict safety filters.
        """
        devices: List[DeviceInfo] = []

        # 1. Linux lsblk parser
        if shutil.which("lsblk"):
            try:
                cmd = ["lsblk", "-J", "-b", "-o", "NAME,PATH,SIZE,RO,RM,MODEL,TRAN,MOUNTPOINT,TYPE,VENDOR,SERIAL"]
                res = subprocess.run(cmd, capture_output=True, text=True, check=True)
                data = json.loads(res.stdout)
                blockdevices = data.get("blockdevices", [])

                for bd in blockdevices:
                    dev_type = bd.get("type", "").lower()
                    if dev_type in ("loop", "ram", "zram"):
                        continue

                    path = bd.get("path") or f"/dev/{bd.get('name', '')}"
                    name = bd.get("name", "")
                    size_bytes = int(bd.get("size") or 0)
                    model = (bd.get("model") or bd.get("name") or "Generic Storage").strip()
                    tran = (bd.get("tran") or "").lower()
                    rm = str(bd.get("rm", "")).strip() in ("1", "true")
                    vendor = (bd.get("vendor") or "").strip()
                    serial = (bd.get("serial") or "").strip()

                    is_usb = tran == "usb" or rm or "sandisk" in model.lower() or "usb" in model.lower()

                    all_mounts = []
                    if bd.get("mountpoint"):
                        all_mounts.append(bd.get("mountpoint"))

                    def extract_child_mounts(children):
                        for child in children:
                            if child.get("mountpoint"):
                                all_mounts.append(child.get("mountpoint"))
                            if "children" in child:
                                extract_child_mounts(child["children"])

                    if "children" in bd:
                        extract_child_mounts(bd["children"])

                    has_system_mount = any(
                        m in cls.PROTECTED_MOUNTPOINTS or m.startswith("/boot") for m in all_mounts
                    )

                    is_protected = has_system_mount or not is_usb or "nvme" in name or name == "sda"
                    if is_usb and not has_system_mount:
                        is_protected = False

                    devices.append(
                        DeviceInfo(
                            path=path,
                            name=name,
                            model=model,
                            size_bytes=size_bytes,
                            is_protected=is_protected,
                            is_usb=is_usb,
                            mountpoint=all_mounts[0] if all_mounts else None,
                            vendor=vendor,
                            serial=serial,
                            tran=tran,
                        )
                    )
                if devices:
                    return devices
            except Exception:
                pass

        # 2. Windows PowerShell Get-Disk parser
        if platform.system().lower() == "windows":
            try:
                ps_cmd = (
                    "Get-Disk | ForEach-Object { "
                    "$d = $_; "
                    "$parts = Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue; "
                    "$letters = ($parts | Where-Object { $_.DriveLetter } | ForEach-Object { $_.DriveLetter + ':' }) -join ','; "
                    "[PSCustomObject]@{ "
                    "Number = $d.Number; "
                    "FriendlyName = $d.FriendlyName; "
                    "SerialNumber = $d.SerialNumber; "
                    "Size = $d.Size; "
                    "BusType = $d.BusType; "
                    "IsBoot = $d.IsBoot; "
                    "IsSystem = $d.IsSystem; "
                    "DriveLetters = $letters "
                    "} } | ConvertTo-Json -Compress"
                )
                res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, check=True)
                raw_out = res.stdout.strip()
                if raw_out:
                    disk_items = json.loads(raw_out)
                    if isinstance(disk_items, dict):
                        disk_items = [disk_items]

                    for d in disk_items:
                        num = d.get("Number", 0)
                        model = d.get("FriendlyName", f"Disk #{num}").strip()
                        size_bytes = int(d.get("Size") or 0)
                        bus_type = str(d.get("BusType", "")).lower()
                        is_boot = bool(d.get("IsBoot"))
                        is_system = bool(d.get("IsSystem"))
                        drive_letters = str(d.get("DriveLetters", ""))
                        serial = str(d.get("SerialNumber", "")).strip()

                        is_usb = "usb" in bus_type or "sandisk" in model.lower() or "cruzer" in model.lower()
                        has_c = "c:" in drive_letters.lower()
                        is_protected = is_boot or is_system or has_c or not is_usb

                        path = f"\\\\.\\PhysicalDrive{num}"
                        name = f"PhysicalDrive{num}"

                        devices.append(
                            DeviceInfo(
                                path=path,
                                name=name,
                                model=f"{model} ({drive_letters or 'RAW'})",
                                size_bytes=size_bytes,
                                is_protected=is_protected,
                                is_usb=is_usb,
                                mountpoint=drive_letters or None,
                                vendor="SanDisk" if "sandisk" in model.lower() else "Generic",
                                serial=serial,
                                tran=bus_type,
                            )
                        )
            except Exception:
                pass

        # 3. Always include Synthetic Forensic Lab Image
        lab_img_path = os.path.abspath("test-data/virtual-disks/vanish_lab_image.img")
        lab_img_size = os.path.getsize(lab_img_path) if os.path.exists(lab_img_path) else 16 * 1024 * 1024

        devices.append(
            DeviceInfo(
                path=lab_img_path,
                name="vanish_lab_image.img",
                model="VANISH Synthetic Forensic Image (16 MB)",
                size_bytes=lab_img_size,
                is_protected=False,
                is_usb=True,
                mountpoint=None,
                vendor="VirtualLab",
                serial="VN-IMG-2026-0819",
                tran="virtual",
            )
        )

        return devices

    @classmethod
    def get_device_by_path(cls, path: str) -> Optional[DeviceInfo]:
        for dev in cls.list_devices():
            if dev.path == path or dev.name == path:
                return dev
        return None
