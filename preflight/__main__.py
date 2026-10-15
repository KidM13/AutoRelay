"""
AutoRelay — preflight self-test entry point.

This file exists so that `python -m preflight` works. It delegates to
the _main() in __init__.py, which contains the actual self-test logic.
"""

import sys
from . import _main

if __name__ == "__main__":
    sys.exit(_main())
