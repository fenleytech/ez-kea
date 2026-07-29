import json
import os
import socket
import threading

import pytest

from ez_kea.core.kea_ctrl import send_command, ControlChannelError


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
    with pytest.raises(ControlChannelError, match="No control-socket"):
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
