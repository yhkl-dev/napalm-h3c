import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_python(code: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )


def test_top_level_telnetlib_shim_supports_direct_import():
    result = _run_python(
        "import telnetlib; "
        "assert telnetlib.__file__.endswith('telnetlib.py'); "
        "assert hasattr(telnetlib, 'Telnet'); "
        "assert hasattr(telnetlib, 'ECHO'); "
        "assert hasattr(telnetlib, 'IAC')"
    )

    assert result.returncode == 0


def test_top_level_telnetlib_shim_supports_package_first_import():
    result = _run_python(
        "import napalm_h3c_comware; "
        "import telnetlib; "
        "assert hasattr(telnetlib, 'Telnet'); "
        "assert hasattr(telnetlib, 'ECHO'); "
        "assert hasattr(telnetlib, 'IAC')"
    )

    assert result.returncode == 0
