#!/usr/bin/env python3
"""Quick scan launcher"""
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from config import SHODAN_API_KEY, DEFAULT_LIMIT_PER_QUERY, DEFAULT_CONCURRENT_VALIDATIONS
except ImportError:
    print("Please create config.py with your Shodan API key")
    print("Copy config_template.py to config.py and edit it")
    sys.exit(1)

import subprocess

# Note: The main_setup() function for the setup.py script is now defined globally.
# The quick_scan.py script will have its own main() function.

def main(): # This is the main for quick_scan.py
    cmd = [
        sys.executable, "shodan_scanner.py",
        "--api-key", SHODAN_API_KEY,
        "--scan",
        "--limit", str(DEFAULT_LIMIT_PER_QUERY),
        "--concurrent", str(DEFAULT_CONCURRENT_VALIDATIONS)
    ]

    print("Starting quick Ollama scan...")
    subprocess.run(cmd)

if __name__ == "__main__":
    main()
