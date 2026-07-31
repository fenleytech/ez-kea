# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
tests/test_kea_version.py

Covers the `kea-dhcp4 -v` probe that decides which control-socket syntax
EZ-KEA generates: Kea 3.0 turned the singular `control-socket` object into a
`control-sockets` list, and we only emit the old spelling for a daemon we can
positively identify as older than that.
"""
import subprocess
from unittest.mock import patch

import pytest

from ez_kea.core.kea_version import detect_kea_version, uses_legacy_control_socket
from ez_kea.core.security import InvalidKeaCommandError


@pytest.fixture(autouse=True)
def allow_kea_binaries(monkeypatch):
    """Simulate kea-dhcp4 being installed and executable, as test_security does —
    validate_kea_command() resolves the binary before we ever exec it."""
    monkeypatch.setattr("ez_kea.core.security.shutil.which", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr("ez_kea.core.security.os.access", lambda path, mode: True)
    monkeypatch.setattr("ez_kea.core.security.os.path.isfile", lambda path: True)


def _completed(stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr=stderr)


@pytest.mark.parametrize("output,expected", [
    ("2.4.1\n", (2, 4, 1)),
    ("2.6.3\n", (2, 6, 3)),
    ("3.0.0\n", (3, 0, 0)),
    ("3.2.1\n", (3, 2, 1)),
    ("10.0.4\n", (10, 0, 4)),  # must not be read as a single digit
])
def test_detect_parses_version_output(output, expected):
    with patch("subprocess.run", return_value=_completed(stdout=output)):
        assert detect_kea_version("kea-dhcp4") == expected


def test_detect_reads_version_from_stderr():
    """A `docker exec` wrapper can put the version on stderr, so both streams
    are searched rather than trusting stdout."""
    with patch("subprocess.run", return_value=_completed(stderr="3.0.1\n")):
        assert detect_kea_version("kea-dhcp4") == (3, 0, 1)


def test_detect_passes_v_flag_to_the_validated_binary():
    with patch("subprocess.run", return_value=_completed(stdout="3.0.0")) as run:
        detect_kea_version("kea-dhcp4")
    assert run.call_args[0][0] == ["kea-dhcp4", "-v"]


@pytest.mark.parametrize("side_effect", [
    FileNotFoundError("no such binary"),
    subprocess.TimeoutExpired(cmd="kea-dhcp4", timeout=5),
    OSError("permission denied"),
])
def test_detect_returns_none_when_the_probe_cannot_run(side_effect):
    """Demo mode has no Kea at all and `docker exec` fails when the container
    is down — neither is an error, both just mean 'unknown'."""
    with patch("subprocess.run", side_effect=side_effect):
        assert detect_kea_version("kea-dhcp4") is None


def test_detect_returns_none_on_unparseable_output():
    with patch("subprocess.run", return_value=_completed(stdout="not a version")):
        assert detect_kea_version("kea-dhcp4") is None


def test_detect_never_execs_a_disallowed_binary():
    """The probe runs an operator-settable command, so it goes through the
    same allowlist as every other exec rather than around it."""
    with patch("subprocess.run") as run:
        assert detect_kea_version("/tmp/evil.sh") is None
    run.assert_not_called()


# ── uses_legacy_control_socket(): which syntax we generate ──────────────────

@pytest.mark.parametrize("version,legacy", [
    ("2.4.1", True),
    ("2.6.3", True),    # last 2.x, now EOL, but still needs the old spelling
    ("3.0.0", False),   # the release that introduced control-sockets
    ("3.2.1", False),
])
def test_legacy_spelling_only_for_pre_3_0(version, legacy):
    with patch("subprocess.run", return_value=_completed(stdout=version)):
        assert uses_legacy_control_socket("kea-dhcp4") is legacy


def test_undetectable_version_gets_the_modern_spelling():
    """'Cannot tell' almost always means 'no Kea installed here yet', not 'an
    ancient Kea' — 2.6 is EOL, so the modern form is the better default."""
    with patch("subprocess.run", side_effect=FileNotFoundError):
        assert uses_legacy_control_socket("kea-dhcp4") is False
