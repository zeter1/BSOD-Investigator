"""PyInstaller/runtime compatibility: close SQLite connections on context exit.

sqlite3.Connection commits/rolls back in ``with`` blocks but does not close the
connection. BSOD Investigator consistently scopes connections with ``with``, so
using a connection subclass that closes at context exit matches the code's
intended lifetime and prevents Windows file locks during self-tests/cleanup.

This file is used both by the Windows packaging preflight and as a PyInstaller
runtime hook. Keep it dependency-free and silent.
"""

from __future__ import annotations

import sqlite3


_ORIGINAL_CONNECT = sqlite3.connect


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def _connect_with_close(*args, **kwargs):
    kwargs.setdefault("factory", _ClosingConnection)
    return _ORIGINAL_CONNECT(*args, **kwargs)


sqlite3.connect = _connect_with_close
