"""
Pip console-script entry point for BinSmasher.

When installed via pip, this module is always installed alongside the source
packages.  It prepends its own directory (= src/) to sys.path BEFORE importing
main, so the sibling packages (analyzer, exploiter, etc.) are always found
regardless of how setuptools wired the editable install.
"""
import os
import sys

# Always prepend src/ (directory of this file) so our packages win over
# any same-named packages that might already be installed in the venv.
_src = os.path.dirname(os.path.abspath(__file__))
if not sys.path or sys.path[0] != _src:
    sys.path.insert(0, _src)

from main import main  # noqa: E402 (import not at top of file — intentional)

if __name__ == "__main__":
    main()
