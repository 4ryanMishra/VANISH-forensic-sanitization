#!/usr/bin/env python3
"""
VANISH - Desktop Application Launcher
SIH 2026 / NTRO PS 26149
"""

import sys
import os

# Ensure repo root is on python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vanish.ui.app import launch_app

if __name__ == "__main__":
    launch_app()
