# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
ez_kea/core/security.py

Server-side guardrails that stop user-controlled configuration values from
being used to gain arbitrary code execution or arbitrary file read/write.
"""
import os
import shlex
import shutil
from typing import List, Optional

from .config_manager import extract_log_file_from_config

# The only binaries EZ-KEA is ever allowed to exec(), by basename. Anything
# else — however it's spelled — is rejected outright. `docker` is included
# only to support the documented `docker exec <container> kea-dhcp4|kea-dhcp6|keactrl`
# testbed pattern; its arguments are further constrained below.
ALLOWED_KEA_BINARIES = {"kea-dhcp4", "kea-dhcp6", "keactrl", "docker"}
ALLOWED_DOCKER_TARGETS = {"kea-dhcp4", "kea-dhcp6", "keactrl"}


class InvalidKeaCommandError(ValueError):
    """Raised when a configured Kea command fails validation."""


class InvalidLogPathError(ValueError):
    """Raised when a configured log file path fails validation."""


def validate_kea_command(cmd_string: str, context: str = "command") -> List[str]:
    """
    Validate that `cmd_string`, once shell-split, resolves to a known-good,
    executable Kea-related binary, and return the parsed argv list.

    The resolved basename must be one of kea-dhcp4/keactrl/docker, and the
    resolved file must actually exist and be executable. The documented
    `docker exec kea-testbed-kea-1 kea-dhcp4` pattern is explicitly supported.

    Raises:
        InvalidKeaCommandError: if the command doesn't parse, doesn't resolve
            to an allowed executable, or that executable isn't runnable.
    """
    try:
        parts = shlex.split(cmd_string or "")
    except ValueError as e:
        raise InvalidKeaCommandError(f"{context}: could not parse command ({e})")

    if not parts:
        raise InvalidKeaCommandError(f"{context}: command is empty")

    argv0 = parts[0]
    basename = os.path.basename(argv0)

    if basename not in ALLOWED_KEA_BINARIES:
        raise InvalidKeaCommandError(
            f"{context}: '{basename}' is not an allowed executable "
            f"(must resolve to one of: {', '.join(sorted(ALLOWED_KEA_BINARIES))})"
        )

    if basename == "docker":
        # Only allow the documented `docker exec <container> <kea-binary>` shape.
        if len(parts) < 4 or parts[1] != "exec":
            raise InvalidKeaCommandError(
                f"{context}: docker invocations must follow 'docker exec <container> "
                "kea-dhcp4|keactrl'"
            )
        inner_binary = os.path.basename(parts[3])
        if inner_binary not in ALLOWED_DOCKER_TARGETS:
            raise InvalidKeaCommandError(
                f"{context}: docker exec target must be kea-dhcp4 or keactrl "
                f"(got '{inner_binary}')"
            )

    resolved: Optional[str] = argv0 if os.path.isabs(argv0) else shutil.which(argv0)
    if not resolved or not os.path.isfile(resolved) or not os.access(resolved, os.X_OK):
        raise InvalidKeaCommandError(
            f"{context}: executable '{argv0}' was not found on PATH or is not executable"
        )

    return parts


def validate_log_file_path(
    candidate: str, dhcp_config_file: str, current_log_file: str,
    dhcp_key: str = "Dhcp4", logger_name: str = "kea-dhcp4",
) -> str:
    """
    Validate a candidate `dhcp_log_file` override submitted through Global
    Settings.

    A candidate is accepted if either:
      * it resolves to exactly the path the Kea config file itself already
        declares as its logger output (the "config-driven auto-detection"
        case, which must keep working unmodified), or
      * it resolves to a path under an allowlisted logs directory (next to
        the active Kea config, next to the currently configured log file, or
        the standard `/var/log/kea` location).

    `dhcp_key`/`logger_name` select which daemon's config/logger to read
    (Dhcp4/kea-dhcp4 by default; pass Dhcp6/kea-dhcp6 for DHCPv6).

    Returns the (unmodified) candidate on success. Raises InvalidLogPathError
    otherwise.
    """
    resolved = os.path.realpath(candidate)

    declared = os.path.realpath(
        extract_log_file_from_config(dhcp_config_file, current_log_file, dhcp_key=dhcp_key, logger_name=logger_name)
    )
    if resolved == declared:
        return candidate

    allowed_dirs = [
        os.path.realpath(os.path.dirname(dhcp_config_file) or "."),
        os.path.realpath(os.path.dirname(current_log_file) or "."),
        "/var/log/kea",
    ]
    for allowed_dir in allowed_dirs:
        try:
            if os.path.commonpath([resolved, allowed_dir]) == allowed_dir:
                return candidate
        except ValueError:
            # commonpath() raises ValueError when paths are on different
            # drives/roots — definitely not a match.
            continue

    raise InvalidLogPathError(
        f"dhcp-log-file: '{candidate}' is outside the allowed log directories and "
        "does not match the Kea config's own declared logger path"
    )
