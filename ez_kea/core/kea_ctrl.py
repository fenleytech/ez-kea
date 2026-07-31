# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
ez_kea/core/kea_ctrl.py

Talks to a running kea-dhcp4/kea-dhcp6 daemon over its own UNIX control
socket using Kea's JSON command-channel protocol. Used for live status checks
(e.g. "ha-heartbeat") that a config-file edit can't answer -- those need a
real response from the running daemon, not the file on disk.

This is the direct-to-daemon control channel, NOT the Kea Control Agent
(kea-ctrl-agent), which ISC deprecated in Kea 3.0 and removed in 3.2. Nothing
here ever went through the agent, so that removal doesn't affect us. What did
change is the config key: Kea 3.0 renamed the singular `control-socket`
object to a `control-sockets` list so a daemon can expose UNIX plus HTTP/HTTPS
at once. find_unix_socket_path() reads both spellings.

Only ever sends commands from the ALLOWED_COMMANDS allowlist: this is a
read-only status probe, not a general command channel, so there's no path
for user input to choose an arbitrary Kea command to run.
"""
import json
import socket
from typing import Any, Dict

ALLOWED_COMMANDS = {"ha-heartbeat", "status-get"}


class ControlChannelError(Exception):
    """Raised when the control socket can't be reached or returns unusable data."""


def find_unix_socket_path(config: Dict[str, Any], dhcp_key: str) -> str:
    """
    Return the UNIX control-socket path configured for `dhcp_key` ("Dhcp4" or
    "Dhcp6"), or "" if the daemon has no UNIX socket.

    Accepts both the pre-3.0 singular `control-socket` object and the Kea 3.0+
    `control-sockets` list, since EZ-KEA edits configs it did not necessarily
    write and Kea itself rewrites the singular form to the list form on any
    `config-write`. A daemon exposing only HTTP/HTTPS yields "" -- we speak the
    UNIX channel only, and reporting "no socket" is more honest than handing an
    HTTP listener to a socket connect().
    """
    daemon = config.get(dhcp_key)
    if not isinstance(daemon, dict):
        return ""

    entries = daemon.get("control-sockets", daemon.get("control-socket"))
    if isinstance(entries, dict):  # singular form, or a list-key holding one object
        entries = [entries]
    if not isinstance(entries, list):
        return ""

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        # socket-type is mandatory in practice, but treat a missing one as
        # "unix": that is the only type that existed when it was optional.
        if entry.get("socket-type", "unix") != "unix":
            continue
        name = entry.get("socket-name")
        if isinstance(name, str) and name:
            return name

    return ""


def send_command(socket_path: str, command: str, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Send a single JSON command to a Kea daemon's UNIX control socket and
    return the parsed JSON response dict.

    Raises ControlChannelError if `command` isn't allowlisted, no socket path
    is configured, the socket can't be reached in time, or the response isn't
    valid JSON.
    """
    if command not in ALLOWED_COMMANDS:
        raise ControlChannelError(f"'{command}' is not an allowed control-channel command")
    if not socket_path:
        raise ControlChannelError(
            "No UNIX control socket is configured for this daemon "
            "(checked both 'control-socket' and 'control-sockets')"
        )

    payload = json.dumps({"command": command}).encode("utf-8")

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(socket_path)
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass  # some platforms disallow shutdown() on AF_UNIX; recv loop below still works

            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
    except (OSError, socket.timeout) as e:
        raise ControlChannelError(f"Could not reach control socket '{socket_path}': {e}")

    raw = b"".join(chunks).decode("utf-8", errors="replace").strip()
    if not raw:
        raise ControlChannelError("Empty response from control socket")

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ControlChannelError(f"Malformed response from control socket: {e}")

    if not isinstance(parsed, dict):
        raise ControlChannelError("Unexpected response shape from control socket")

    return parsed
