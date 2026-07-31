# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import json
import os
import socket
import threading

import pytest

from ez_kea.core.kea_ctrl import send_command, find_unix_socket_path, ControlChannelError


def _run_fake_kea_socket(path, response_payload):
    """Accept exactly one connection on a UNIX socket, read the request,
    and reply with response_payload (a dict, JSON-encoded)."""
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)

    def _serve():
        conn, _ = srv.accept()
        with conn:
            chunks = []
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            conn.sendall(json.dumps(response_payload).encode("utf-8"))

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return srv, thread


def test_send_command_rejects_unknown_command():
    with pytest.raises(ControlChannelError, match="not an allowed"):
        send_command("/tmp/whatever.sock", "config-set")


def test_send_command_rejects_empty_socket_path():
    with pytest.raises(ControlChannelError, match="No UNIX control socket"):
        send_command("", "ha-heartbeat")


def test_send_command_missing_socket_raises(tmp_path):
    missing = str(tmp_path / "does-not-exist.sock")
    with pytest.raises(ControlChannelError, match="Could not reach"):
        send_command(missing, "ha-heartbeat", timeout=1.0)


def test_send_command_success(tmp_path):
    sock_path = str(tmp_path / "kea-dhcp4-ctrl.sock")
    expected = {"result": 0, "text": "HA peer status returned.", "arguments": {"state": "hot-standby"}}
    srv, thread = _run_fake_kea_socket(sock_path, expected)
    try:
        response = send_command(sock_path, "ha-heartbeat", timeout=2.0)
        assert response == expected
    finally:
        srv.close()
        thread.join(timeout=2)


# ── find_unix_socket_path(): pre-3.0 vs Kea 3.0+ control-socket spelling ────

@pytest.mark.parametrize("dhcp_key", ["Dhcp4", "Dhcp6"])
def test_finds_socket_in_legacy_singular_form(dhcp_key):
    """Pre-3.0 configs use a single `control-socket` object."""
    config = {dhcp_key: {"control-socket": {
        "socket-type": "unix", "socket-name": "/var/run/kea/ctrl.sock",
    }}}
    assert find_unix_socket_path(config, dhcp_key) == "/var/run/kea/ctrl.sock"


@pytest.mark.parametrize("dhcp_key", ["Dhcp4", "Dhcp6"])
def test_finds_socket_in_kea3_list_form(dhcp_key):
    """Kea 3.0 renamed the key to `control-sockets` and made it a list."""
    config = {dhcp_key: {"control-sockets": [{
        "socket-type": "unix", "socket-name": "/var/run/kea/ctrl.sock",
    }]}}
    assert find_unix_socket_path(config, dhcp_key) == "/var/run/kea/ctrl.sock"


def test_finds_unix_socket_alongside_http_listener():
    """The Kea 3.0 direct-API layout: a UNIX socket and an HTTP listener
    side by side. We must pick the UNIX one regardless of ordering."""
    config = {"Dhcp4": {"control-sockets": [
        {"socket-type": "http", "socket-address": "127.0.0.1", "socket-port": 8000},
        {"socket-type": "unix", "socket-name": "/var/run/kea/ctrl.sock"},
    ]}}
    assert find_unix_socket_path(config, "Dhcp4") == "/var/run/kea/ctrl.sock"


def test_http_only_daemon_reports_no_unix_socket():
    """A daemon exposing only HTTP has no channel we can speak; returning ""
    surfaces a clear error instead of connect()ing to a nonexistent path."""
    config = {"Dhcp4": {"control-sockets": [
        {"socket-type": "http", "socket-address": "127.0.0.1", "socket-port": 8000},
    ]}}
    assert find_unix_socket_path(config, "Dhcp4") == ""


def test_socket_type_defaults_to_unix_when_omitted():
    config = {"Dhcp4": {"control-sockets": [{"socket-name": "/var/run/kea/ctrl.sock"}]}}
    assert find_unix_socket_path(config, "Dhcp4") == "/var/run/kea/ctrl.sock"


@pytest.mark.parametrize("config", [
    {},
    {"Dhcp4": {}},
    {"Dhcp4": None},
    {"Dhcp4": {"control-sockets": []}},
    {"Dhcp4": {"control-sockets": "not-a-list"}},
    {"Dhcp4": {"control-sockets": [None, "junk"]}},
    {"Dhcp4": {"control-socket": {"socket-type": "unix"}}},      # no socket-name
    {"Dhcp4": {"control-socket": {"socket-type": "unix", "socket-name": ""}}},
])
def test_missing_or_malformed_socket_config_returns_empty(config):
    """A hand-edited or partial config must not crash the HA status endpoint."""
    assert find_unix_socket_path(config, "Dhcp4") == ""


def test_send_command_malformed_json_raises(tmp_path):
    sock_path = str(tmp_path / "kea-dhcp4-ctrl.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(1)

    def _serve():
        conn, _ = srv.accept()
        with conn:
            while conn.recv(65536):
                pass
            conn.sendall(b"not json")

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        with pytest.raises(ControlChannelError, match="Malformed response"):
            send_command(sock_path, "ha-heartbeat", timeout=2.0)
    finally:
        srv.close()
        thread.join(timeout=2)
