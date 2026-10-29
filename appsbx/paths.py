"""Stable paths for an installed appsbx copy.

The source checkout intentionally keeps its historical ``sandbox-state``
directory.  Installed launchers set ``APPSBX_STATE_ROOT`` so executable code
can stay read-only while profiles, logs, downloads, and identities remain
per-user under the XDG state directory.
"""

from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def state_root() -> Path:
    """Return the writable state root without accepting relative overrides."""
    configured = os.environ.get("APPSBX_STATE_ROOT")
    if not configured:
        return PROJECT_ROOT / "sandbox-state"
    path = Path(configured).expanduser()
    if not path.is_absolute():
        raise ValueError("APPSBX_STATE_ROOT must be an absolute path")
    return path.resolve()
