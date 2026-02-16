#!/usr/bin/env python3
"""
SPIDER - Multi-Agent Reverse Engineering Pipeline.
Entry point: always launches the interactive CLI.
If a binary path is given as argument, it is loaded automatically.
"""

import os
import sys

# Ensure the project root is on sys.path so imports work from any cwd.
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def main():
    from ui.cli import main as cli_main
    cli_main()


if __name__ == "__main__":
    main()
