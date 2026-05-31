"""Compatibility shim for Python 3.13+ where stdlib telnetlib was removed.

This top-level module is packaged into the wheel so imports like
``import telnetlib`` continue to succeed before ``napalm_h3c_comware`` is
imported. The implementation is vendored from CPython 3.12.
"""

from napalm_h3c_comware._compat import telnetlib as _compat_telnetlib

_SKIP_EXPORTS = {"__builtins__", "__cached__", "__file__", "__loader__", "__name__", "__package__", "__spec__"}

for _name, _value in vars(_compat_telnetlib).items():
    if _name not in _SKIP_EXPORTS:
        globals()[_name] = _value
