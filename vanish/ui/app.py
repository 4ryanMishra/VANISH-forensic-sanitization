"""
VANISH - Digital Forensics & Data Sanitization Workstation
Unified PySide6 Desktop GUI with non-blocking QThread execution,
device safety gates, real-time forensic carving, NIST SP 800-88 sanitization,
L4 auto-carve verification, and tamper-evident SHA-256 audit ledger.
"""

import sys
import os
import json
from typing import List, Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QColor, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTabWidget,
    QLabel,
    QComboBox,
    QPushButton,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QLineEdit,
    QTextEdit,
    QGroupBox,
    QFileDialog,
    QFrame,
)

from ..device.discovery import DeviceDiscovery, DeviceInfo
from ..forensic.carving import ForensicCarver
from ..forensic.artifacts import RecoveredArtifact
from ..sanitization.executor import SanitizationExecutor
from ..verification.engine import VerificationEngine
from ..audit.chain import AuditChain


# ==============================================================================
# QThread Workers for Non-Blocking Background Tasks
# ==============================================================================

class CarvingWorker(QThread):
    progress_updated = Signal(int, int, int, int)  # offset, total, pct, artifact_count
    artifact_found = Signal(object)
    task_completed = Signal(list)
    error_occurred = Signal(str)

    def __init__(self, target_path: str):
        super().__init__()
        self.target_path = target_path

    def run(self):
        try:
            carver = ForensicCarver(self.target_path)

            def on_progress(offset, total, pct, count):
                self.progress_updated.emit(offset, total, pct, count)

            artifacts = carver.scan(progress_callback=on_progress)
            self.task_completed.emit(artifacts)
        except Exception as e:
            self.error_occurred.emit(str(e))


class SanitizationVerificationWorker(QThread):
    progress_updated = Signal(str, int)  # status_msg, percentage
    task_completed = Signal(dict, dict)  # sanitize_summary, verif_report
    error_occurred = Signal(str)

    def __init__(self, device: DeviceInfo):
        super().__init__()
        self.device = device

    def run(self):
        try:
            # 1. Sanitize
            def on_sanitize_progress(written, total, pct):
                mb_w = written // (1024 * 1024)
                mb_tot = total // (1024 * 1024)
                self.progress_updated.emit(f"Overwriting NIST SP 800-88 Clear zeroes: {mb_w}/{mb_tot} MB ({pct}%)", int(pct * 0.5))

            summary = SanitizationExecutor.sanitize_device(self.device, progress_callback=on_sanitize_progress)

            # 2. Verify
            def on_verif_progress(msg, pct):
                self.progress_updated.emit(msg, 50 + int(pct * 0.5))

            verif_report = VerificationEngine.verify_sanitization(self.device, progress_callback=on_verif_progress)
            self.task_completed.emit(summary, verif_report)
        except Exception as e:
            self.error_occurred.emit(str(e))


# ==============================================================================
# Main Workstation Window
# ==============================================================================

class VanishMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VANISH — Digital Forensics & Data Sanitization Workstation (NTRO PS 26149)")
        self.resize(1180, 820)
        self.setMinimumSize(980, 680)

        self.audit_chain = AuditChain()
        self.devices: List[DeviceInfo] = []
        self.selected_device: Optional[DeviceInfo] = None
        self.recovered_artifacts: List[RecoveredArtifact] = []

        self._apply_theme()
        self._init_ui()
        self._refresh_device_list()

    def _apply_theme(self):
        self.setStyleSheet(
            """
            QMainWindow { background-color: #0b0f19; }
            QWidget { color: #e2e8f0; font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
            QTabWidget::pane { border: 1px solid #1e293b; background-color: #0f172a; border-radius: 8px; }
            QTabBar::tab {
                background-color: #1e293b; color: #94a3b8; padding: 10px 24px;
                border-top-left-radius: 6px; border-top-right-radius: 6px; margin-right: 4px; font-weight: bold;
            }
            QTabBar::tab:selected { background-color: #0f172a; color: #38bdf8; border-top: 2px solid #38bdf8; }
            QGroupBox {
                border: 1px solid #1e293b; border-radius: 8px; margin-top: 14px;
                font-weight: bold; color: #94a3b8; padding: 12px;
            }
            QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; }
            QPushButton {
                background-color: #2563eb; color: #ffffff; border: none; border-radius: 6px;
                padding: 8px 16px; font-weight: 600; font-size: 13px;
            }
            QPushButton:hover { background-color: #1d4ed8; }
            QPushButton:disabled { background-color: #334155; color: #64748b; }
            QPushButton#dangerBtn { background-color: #dc2626; }
            QPushButton#dangerBtn:hover { background-color: #b91c1c; }
            QPushButton#dangerBtn:disabled { background-color: #334155; color: #64748b; }
            QPushButton#secondaryBtn { background-color: #334155; }
            QPushButton#secondaryBtn:hover { background-color: #475569; }
            QTableWidget {
                background-color: #0b0f19; border: 1px solid #1e293b; border-radius: 6px;
                gridline-color: #1e293b; color: #f8fafc; font-size: 12px;
            }
            QHeaderView::section {
                background-color: #1e293b; color: #94a3b8; padding: 6px; border: none;
                font-weight: bold; font-size: 11px;
            }
            QProgressBar {
                border: 1px solid #1e293b; border-radius: 6px; text-align: center;
                color: #ffffff; font-weight: bold; background-color: #1e293b; height: 18px;
            }
            QProgressBar::chunk { background-color: #38bdf8; border-radius: 5px; }
            QComboBox, QLineEdit {
                background-color: #1e293b; border: 1px solid #334155; border-radius: 6px;
                padding: 6px 12px; color: #f8fafc; font-size: 13px;
            }
            QComboBox:focus, QLineEdit:focus { border: 1px solid #38bdf8; }
            QTextEdit {
                background-color: #0b0f19; border: 1px solid #1e293b; border-radius: 6px;
                color: #38bdf8; font-family: 'Consolas', monospace; font-size: 11px;
            }
            """
        )

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(14)

        # ----------------------------------------------------------------------
        # Top Header: Device Selection & Invariant Safety Status
        # ----------------------------------------------------------------------
        header_group = QGroupBox("TARGET STORAGE DEVICE & SAFETY GATES")
        header_layout = QHBoxLayout(header_group)

        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(420)
        self.device_combo.currentIndexChanged.connect(self._on_device_changed)
        header_layout.addWidget(self.device_combo)

        self.refresh_btn = QPushButton("Refresh Bus")
        self.refresh_btn.setObjectName("secondaryBtn")
        self.refresh_btn.clicked.connect(self._refresh_device_list)
        header_layout.addWidget(self.refresh_btn)

        header_layout.addSpacing(16)

        # Device details badge
        self.device_info_label = QLabel("Path: - | Size: -")
        self.device_info_label.setStyleSheet("color: #94a3b8; font-family: Consolas; font-size: 12px;")
        header_layout.addWidget(self.device_info_label)

        header_layout.addStretch()

        # Protection status badge
        self.safety_badge = QLabel("TARGET STATUS")
        self.safety_badge.setStyleSheet(
            "padding: 6px 14px; border-radius: 6px; font-weight: bold; font-size: 12px; font-family: Consolas;"
        )
        header_layout.addWidget(self.safety_badge)

        main_layout.addWidget(header_group)

        # ----------------------------------------------------------------------
        # Main Workstation Tabs
        # ----------------------------------------------------------------------
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs, stretch=1)

        self._build_recovery_tab()
        self._build_sanitization_tab()
        self._build_audit_tab()

    # ==========================================================================
    # Tab 1: Forensic Recovery
    # ==========================================================================
    def _build_recovery_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Action bar
        action_layout = QHBoxLayout()
        self.start_carve_btn = QPushButton("Start Read-Only Sector Scan")
        self.start_carve_btn.clicked.connect(self._start_carving)
        action_layout.addWidget(self.start_carve_btn)

        self.export_artifact_btn = QPushButton("Export Selected Artifact")
        self.export_artifact_btn.setObjectName("secondaryBtn")
        self.export_artifact_btn.setEnabled(False)
        self.export_artifact_btn.clicked.connect(self._export_selected_artifact)
        action_layout.addWidget(self.export_artifact_btn)

        self.export_manifest_btn = QPushButton("Export Manifest (JSON)")
        self.export_manifest_btn.setObjectName("secondaryBtn")
        self.export_manifest_btn.setEnabled(False)
        self.export_manifest_btn.clicked.connect(self._export_manifest)
        action_layout.addWidget(self.export_manifest_btn)

        action_layout.addStretch()

        self.write_block_label = QLabel("Write-Block Guard: READ-ONLY ACTIVE [OK]")
        self.write_block_label.setStyleSheet("color: #10b981; font-weight: bold; font-family: Consolas; font-size: 12px;")
        action_layout.addWidget(self.write_block_label)

        layout.addLayout(action_layout)

        # Progress bar & status
        self.carve_progress = QProgressBar()
        self.carve_progress.setValue(0)
        layout.addWidget(self.carve_progress)

        self.carve_status_label = QLabel("Ready to scan target media. Structural container parsing enabled.")
        self.carve_status_label.setStyleSheet("color: #94a3b8; font-size: 11px; font-family: Consolas;")
        layout.addWidget(self.carve_status_label)

        # Artifacts table
        self.artifacts_table = QTableWidget(0, 7)
        self.artifacts_table.setHorizontalHeaderLabels(
            ["Artifact ID", "Type", "Offset", "Size (KB)", "Confidence", "Validation Status", "SHA-256 (Canonical Evidence)"]
        )
        self.artifacts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.artifacts_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.artifacts_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.artifacts_table.itemSelectionChanged.connect(
            lambda: self.export_artifact_btn.setEnabled(len(self.artifacts_table.selectedItems()) > 0)
        )
        layout.addWidget(self.artifacts_table, stretch=1)

        self.tabs.addTab(tab, "1. Forensic Recovery & Carving")

    # ==========================================================================
    # Tab 2: Secure Sanitization & L4 Verification
    # ==========================================================================
    def _build_sanitization_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        # Sanitization config
        config_group = QGroupBox("SANITIZATION POLICY & TARGET CONFIRMATION")
        config_layout = QVBoxLayout(config_group)
        config_layout.setSpacing(10)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Standard Applied:"))
        self.policy_combo = QComboBox()
        self.policy_combo.addItems([
            "NIST SP 800-88 Rev 1 (Clear) — Single-Pass Zero Overwrite",
            "DoD 5220.22-M (3-Pass Multi-Pattern Overwrite)",
        ])
        row1.addWidget(self.policy_combo, stretch=1)
        config_layout.addLayout(row1)

        # Confirmation barrier
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Safety Barrier (Type target disk name to confirm):"))
        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("e.g. sdb or vanish_lab_image.img")
        self.confirm_input.textChanged.connect(self._check_confirm_barrier)
        row2.addWidget(self.confirm_input, stretch=1)
        config_layout.addLayout(row2)

        self.sanitize_btn = QPushButton("Arm, Sanitize & Execute L4 Verification")
        self.sanitize_btn.setObjectName("dangerBtn")
        self.sanitize_btn.setEnabled(False)
        self.sanitize_btn.clicked.connect(self._start_sanitization)
        config_layout.addWidget(self.sanitize_btn)

        layout.addWidget(config_group)

        # Progress bar
        self.sanitize_progress = QProgressBar()
        self.sanitize_progress.setValue(0)
        layout.addWidget(self.sanitize_progress)

        # Verification checklist & log
        verif_group = QGroupBox("CLOSED-LOOP MULTI-LEVEL VERIFICATION MATRIX (L1 - L4)")
        verif_layout = QVBoxLayout(verif_group)

        self.verif_log = QTextEdit()
        self.verif_log.setReadOnly(True)
        self.verif_log.setPlaceholderText("Verification logs will appear here after sanitization completes...")
        verif_layout.addWidget(self.verif_log)

        layout.addWidget(verif_group, stretch=1)

        self.tabs.addTab(tab, "2. Sanitization & L4 Verification")

    # ==========================================================================
    # Tab 3: Tamper-Evident Audit Ledger
    # ==========================================================================
    def _build_audit_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        action_layout = QHBoxLayout()
        self.verify_ledger_btn = QPushButton("Verify Cryptographic Hash Chain Integrity")
        self.verify_ledger_btn.clicked.connect(self._verify_ledger_integrity)
        action_layout.addWidget(self.verify_ledger_btn)

        self.refresh_audit_btn = QPushButton("Refresh Events")
        self.refresh_audit_btn.setObjectName("secondaryBtn")
        self.refresh_audit_btn.clicked.connect(self._load_audit_events)
        action_layout.addWidget(self.refresh_audit_btn)

        action_layout.addStretch()
        layout.addLayout(action_layout)

        # Audit events table
        self.audit_table = QTableWidget(0, 6)
        self.audit_table.setHorizontalHeaderLabels(
            ["Event ID", "Timestamp (UTC)", "Operation", "Target Path", "Status", "SHA-256 Hash Link"]
        )
        self.audit_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.audit_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        layout.addWidget(self.audit_table, stretch=1)

        self.tabs.addTab(tab, "3. Tamper-Evident Audit Ledger")

    # ==========================================================================
    # Logic & Event Handlers
    # ==========================================================================
    def _refresh_device_list(self):
        self.devices = DeviceDiscovery.list_devices()
        self.device_combo.clear()

        for dev in self.devices:
            prot_str = " [PROTECTED OS]" if dev.is_protected else " [READY TARGET]"
            self.device_combo.addItem(f"{dev.name} - {dev.model} ({dev.size_gb} GB){prot_str}", dev)

        if self.devices:
            # Prefer selecting first unprotected device
            target_idx = 0
            for idx, d in enumerate(self.devices):
                if not d.is_protected:
                    target_idx = idx
                    break
            self.device_combo.setCurrentIndex(target_idx)
            self._on_device_changed(target_idx)

        self._load_audit_events()

    def _on_device_changed(self, index: int):
        if index < 0 or index >= len(self.devices):
            return
        self.selected_device = self.devices[index]
        dev = self.selected_device

        self.device_info_label.setText(f"Path: {dev.path} | Size: {dev.size_gb} GB ({dev.size_bytes:,} B) | Serial: {dev.serial or 'N/A'}")

        if dev.is_protected:
            self.safety_badge.setText("FAIL-CLOSED: PROTECTED DRIVE")
            self.safety_badge.setStyleSheet("background-color: #7f1d1d; color: #fca5a5; border: 1px solid #ef4444; border-radius: 6px; font-weight: bold;")
        else:
            self.safety_badge.setText("LAB TARGET: READY FOR SANITIZATION")
            self.safety_badge.setStyleSheet("background-color: #064e3b; color: #6ee7b7; border: 1px solid #10b981; border-radius: 6px; font-weight: bold;")

        self._check_confirm_barrier()

    def _check_confirm_barrier(self):
        if not self.selected_device or self.selected_device.is_protected:
            self.sanitize_btn.setEnabled(False)
            return

        user_typed = self.confirm_input.text().strip()
        expected = self.selected_device.name.strip()
        matches = (user_typed.lower() == expected.lower()) or (user_typed.lower() == self.selected_device.path.lower())
        self.sanitize_btn.setEnabled(matches)

    # --------------------------------------------------------------------------
    # Carving Flow
    # --------------------------------------------------------------------------
    def _start_carving(self):
        if not self.selected_device:
            return

        self.start_carve_btn.setEnabled(False)
        self.carve_progress.setValue(0)
        self.artifacts_table.setRowCount(0)
        self.recovered_artifacts.clear()
        self.export_artifact_btn.setEnabled(False)
        self.export_manifest_btn.setEnabled(False)

        target_path = self.selected_device.path
        self.carve_status_label.setText(f"Streaming raw sectors from '{target_path}' in read-only write-blocked mode...")

        self.carve_worker = CarvingWorker(target_path)
        self.carve_worker.progress_updated.connect(self._on_carve_progress)
        self.carve_worker.task_completed.connect(self._on_carve_completed)
        self.carve_worker.error_occurred.connect(self._on_carve_error)
        self.carve_worker.start()

    def _on_carve_progress(self, offset: int, total: int, pct: int, count: int):
        self.carve_progress.setValue(pct)
        mb_scanned = round(offset / (1024 * 1024), 2)
        mb_total = round(total / (1024 * 1024), 2)
        self.carve_status_label.setText(f"Scanned {mb_scanned} / {mb_total} MB ({pct}%) | Artifacts Recovered: {count}")

    def _on_carve_completed(self, artifacts: List[RecoveredArtifact]):
        self.start_carve_btn.setEnabled(True)
        self.carve_progress.setValue(100)
        self.recovered_artifacts = artifacts

        self.artifacts_table.setRowCount(len(artifacts))
        for row, art in enumerate(artifacts):
            self.artifacts_table.setItem(row, 0, QTableWidgetItem(art.artifact_id))
            self.artifacts_table.setItem(row, 1, QTableWidgetItem(art.file_type))
            self.artifacts_table.setItem(row, 2, QTableWidgetItem(f"0x{art.detected_offset:X} ({art.detected_offset})"))
            self.artifacts_table.setItem(row, 3, QTableWidgetItem(f"{art.size_bytes / 1024:.2f}"))
            self.artifacts_table.setItem(row, 4, QTableWidgetItem(f"{art.confidence_score * 100:.0f}%"))
            self.artifacts_table.setItem(row, 5, QTableWidgetItem(art.validation_status))
            self.artifacts_table.setItem(row, 6, QTableWidgetItem(art.sha256_hash))

        self.carve_status_label.setText(f"Carving scan completed. Recovered {len(artifacts)} valid artifacts with SHA-256 evidence integrity.")
        self.export_manifest_btn.setEnabled(len(artifacts) > 0)

        self.audit_chain.append_event(
            operation=f"FORENSIC_CARVE_SCAN: {len(artifacts)} artifacts recovered",
            target_path=self.selected_device.path if self.selected_device else "unknown",
            status="SUCCESS",
            details=f"Carved {len(artifacts)} valid files across {self.carve_progress.maximum()} sectors.",
        )
        self._load_audit_events()

    def _on_carve_error(self, err_msg: str):
        self.start_carve_btn.setEnabled(True)
        self.carve_status_label.setText(f"Carving Error: {err_msg}")
        QMessageBox.critical(self, "Forensic Carving Error", f"Failed scanning raw sectors:\n{err_msg}")

    def _export_selected_artifact(self):
        selected_rows = self.artifacts_table.selectionModel().selectedRows()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        art = self.recovered_artifacts[row]

        ext = art.file_type.lower()
        save_path, _ = QFileDialog.getSaveFileName(self, "Export Recovered Artifact", f"{art.artifact_id}.{ext}")
        if save_path:
            # Extract raw bytes from source at offset
            try:
                with open(art.source_device, "rb") as f:
                    f.seek(art.detected_offset)
                    payload = f.read(art.size_bytes)
                with open(save_path, "wb") as f_out:
                    f_out.write(payload)
                QMessageBox.information(self, "Artifact Exported", f"Artifact successfully saved to:\n{save_path}\n\nSHA-256: {art.sha256_hash}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed saving artifact:\n{e}")

    def _export_manifest(self):
        save_path, _ = QFileDialog.getSaveFileName(self, "Export Forensic Evidence Manifest", "forensic_manifest.json", "JSON Files (*.json)")
        if save_path:
            data = {
                "manifest_version": "1.0.0",
                "source_device": self.selected_device.path if self.selected_device else "",
                "total_artifacts": len(self.recovered_artifacts),
                "artifacts": [a.to_dict() for a in self.recovered_artifacts],
            }
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            QMessageBox.information(self, "Manifest Exported", f"Evidence manifest exported to:\n{save_path}")

    # --------------------------------------------------------------------------
    # Sanitization & Verification Flow
    # --------------------------------------------------------------------------
    def _start_sanitization(self):
        if not self.selected_device or self.selected_device.is_protected:
            QMessageBox.critical(self, "Safety Gate Blocked", "Cannot sanitize protected drive.")
            return

        reply = QMessageBox.warning(
            self,
            "CONFIRM DISK SANITIZATION",
            f"Are you ABSOLUTELY sure you want to sanitize device:\n\n"
            f"Path: {self.selected_device.path}\n"
            f"Model: {self.selected_device.model}\n\n"
            "This will overwrite all blocks with NIST SP 800-88 Clear zeroes (0x00).",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        self.sanitize_btn.setEnabled(False)
        self.sanitize_progress.setValue(0)
        self.verif_log.clear()
        self.verif_log.append(">>> Initializing NIST SP 800-88 Clear Sanitization Sequence...")

        self.san_worker = SanitizationVerificationWorker(self.selected_device)
        self.san_worker.progress_updated.connect(self._on_sanitize_progress)
        self.san_worker.task_completed.connect(self._on_sanitize_completed)
        self.san_worker.error_occurred.connect(self._on_sanitize_error)
        self.san_worker.start()

    def _on_sanitize_progress(self, msg: str, pct: int):
        self.sanitize_progress.setValue(pct)
        self.verif_log.append(f"[*] {msg}")

    def _on_sanitize_completed(self, summary: dict, verif_report: dict):
        self.sanitize_progress.setValue(100)
        self.confirm_input.clear()
        self._check_confirm_barrier()

        self.verif_log.append("\n=======================================================")
        self.verif_log.append(">>> POST-SANITIZATION MULTI-LEVEL VERIFICATION REPORT")
        self.verif_log.append("=======================================================")

        for lvl in verif_report.get("levels", []):
            status = "PASSED [OK]" if lvl["passed"] else "FAILED [X]"
            self.verif_log.append(f"\n[{lvl['level']}]: {status} (Confidence: {lvl['confidence_pct']}%)")
            for ev in lvl.get("evidence", []):
                self.verif_log.append(f"   * {ev}")

        overall = verif_report.get("overall_passed", False)
        conf = verif_report.get("confidence_pct", 0)

        if overall:
            self.verif_log.append(f"\n[FINAL VERDICT]: UNRECOVERABILITY CERTIFIED (Confidence: {conf}%) [OK]")
            QMessageBox.information(
                self,
                "Sanitization & L4 Verification Succeeded",
                f"Device '{self.selected_device.path}' was successfully sanitized.\n\n"
                f"L1 Logical: PASSED\nL2 Host-Visible: PASSED\nL4 Forensic Auto-Carve: 0 ARTIFACTS RECOVERED (PASSED)\n\n"
                f"Overall Confidence: {conf}%",
            )
        else:
            self.verif_log.append("\n[FINAL VERDICT]: VERIFICATION FAILED [X]")
            QMessageBox.critical(self, "Verification Warning", "Sanitization or verification encountered residual artifacts.")

        self.audit_chain.append_event(
            operation=f"SANITIZATION_AND_L4_VERIFICATION: {summary.get('method')}",
            target_path=self.selected_device.path if self.selected_device else "unknown",
            status="SUCCESS" if overall else "FAILED",
            details=f"Wrote {summary.get('bytes_written', 0)} bytes. L1/L2/L4 Confidence: {conf}%.",
        )
        self._load_audit_events()

    def _on_sanitize_error(self, err_msg: str):
        self.sanitize_btn.setEnabled(True)
        self.verif_log.append(f"\n[ERROR]: {err_msg}")
        QMessageBox.critical(self, "Sanitization Error", f"Operation aborted:\n{err_msg}")

    # --------------------------------------------------------------------------
    # Audit Trail Flow
    # --------------------------------------------------------------------------
    def _load_audit_events(self):
        events = self.audit_chain.get_all_events()
        self.audit_table.setRowCount(len(events))

        for row, evt in enumerate(events):
            self.audit_table.setItem(row, 0, QTableWidgetItem(evt["event_id"]))
            self.audit_table.setItem(row, 1, QTableWidgetItem(evt["timestamp"]))
            self.audit_table.setItem(row, 2, QTableWidgetItem(evt["operation"]))
            self.audit_table.setItem(row, 3, QTableWidgetItem(evt["target_path"]))
            self.audit_table.setItem(row, 4, QTableWidgetItem(evt["status"]))
            self.audit_table.setItem(row, 5, QTableWidgetItem(evt["sha256_hash"]))

    def _verify_ledger_integrity(self):
        is_valid, msg = self.audit_chain.verify_chain_integrity()
        if is_valid:
            QMessageBox.information(self, "Cryptographic Ledger Verified", f"Audit Ledger Chain-of-Custody Verified:\n\n{msg}")
        else:
            QMessageBox.critical(self, "Tamper Detected", f"CRITICAL SECURITY ALERT:\n\n{msg}")


def launch_app():
    app = QApplication(sys.argv)
    window = VanishMainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    launch_app()
