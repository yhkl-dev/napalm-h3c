import sys

__version__ = "0.1.0"

if sys.version_info >= (3, 13):
    try:
        import telnetlib  # noqa: F401
    except ModuleNotFoundError:
        from ._compat import telnetlib as _compat_telnetlib

        sys.modules.setdefault("telnetlib", _compat_telnetlib)
