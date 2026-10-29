"""Runs ONLY in the restricted container. Output is not a trusted attestation."""
import json
import os
import platform
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, '/source')
import sympy
import mpmath

identity = {'python': platform.python_version(), 'mpmath': mpmath.__version__,
            'sympy_file': str(Path(sympy.__file__).resolve()), 'assertions': __debug__}
if identity != {'python': '3.9.25', 'mpmath': '1.3.0',
                'sympy_file': '/source/sympy/__init__.py', 'assertions': True}:
    raise RuntimeError('Wrong interpreter, dependency, import path or assertions')
print('RALPH_IDENTITY ' + json.dumps(identity, sort_keys=True), flush=True)
os.chdir('/source')
cmd = [sys.executable, '-B', 'bin/test', '-v', '--no-colors', '--no-subprocess',
       '--seed', '1', 'sympy/polys/tests/test_monomials.py']
sys.exit(subprocess.call(cmd))
