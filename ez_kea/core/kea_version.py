# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
ez_kea/core/kea_version.py

Detects the version of the Kea daemon EZ-KEA is managing, so the config we
*generate* matches the syntax that daemon actually parses.

One thing currently depends on this: Kea 3.0 replaced the singular
`control-socket` object with a `control-sockets` list. Kea 3.0 still accepts
the old spelling (it reads it as a one-element list), but ISC does not
document that alias surviving the 3.2 removal of the Control Agent, and Kea
2.6 -- the last 2.x -- is already EOL. So the skeletons we write default to
the 3.0+ list form, and fall back to the singular object only when we
positively identify a pre-3.0 daemon.

Reading is handled separately and unconditionally accepts both spellings; see
find_unix_socket_path() in ez_kea/core/kea_ctrl.py.
"""
import re
import subprocess
from typing import Optional, Tuple

from .security import validate_kea_command, InvalidKeaCommandError

# The Kea release that renamed `control-socket` to the `control-sockets` list.
CONTROL_SOCKETS_LIST_SINCE = (3, 0)

_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")

KeaVersion = Tuple[int, int, int]


def detect_kea_version(kea_cmd: str, timeout: float = 5.0) -> Optional[KeaVersion]:
    """
    Return the (major, minor, patch) version reported by `kea_cmd -v`, or None
    if it cannot be determined.

    None is a normal outcome, not an error: EZ-KEA runs in demo mode with no
    Kea installed at all, and the documented `docker exec <container> kea-dhcp4`
    form fails whenever that container is down. Callers must treat None as
    "assume current Kea" rather than as a failure to report.

    The command goes through validate_kea_command() for the same reason every
    other exec does -- kea_dhcp4_cmd is operator-settable, so it is never
    handed to subprocess without passing the basename allowlist first.
    """
    try:
        argv = validate_kea_command(kea_cmd, "kea-version-probe")
    except InvalidKeaCommandError:
        return None

    try:
        result = subprocess.run(
            argv + ["-v"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    # `kea-dhcp4 -v` prints a bare version to stdout, but a `docker exec` that
    # fails writes to stderr -- search both rather than trusting the stream.
    match = _VERSION_RE.search(f"{result.stdout}\n{result.stderr}")
    if not match:
        return None

    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def uses_legacy_control_socket(kea_cmd: str) -> bool:
    """
    True only when we positively identify a Kea older than 3.0, which needs the
    singular `control-socket` object rather than the `control-sockets` list.

    An undetectable version deliberately yields False. Kea 2.6 was the last 2.x
    and is EOL, so "cannot tell" is far more likely to mean "no Kea installed
    here yet" than "an ancient Kea" -- and writing the modern form is the
    better bet in that case.
    """
    version = detect_kea_version(kea_cmd)
    return version is not None and version < CONTROL_SOCKETS_LIST_SINCE
