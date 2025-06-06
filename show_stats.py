#!/usr/bin/env python3
"""Database stats viewer"""
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from config import SHODAN_API_KEY
except ImportError:
    print("Please create config.py with your Shodan API key")
    print("Copy config_template.py to config.py and edit it")
    sys.exit(1)

import subprocess

def main():
    cmd = [
        sys.executable, "shodan_scanner.py",
        "--api-key", SHODAN_API_KEY,
        "--stats"
    ]

    subprocess.run(cmd)

if __name__ == "__main__":
    main()
