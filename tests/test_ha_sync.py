# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
Config sync to HA peers over Kea's own HTTP control API (core/ha_sync.py and
the Apply route). A small fake Kea API stands in for the peer.
"""
import base64
import copy
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from flask import jsonify
from werkzeug.datastructures import MultiDict

from ez_kea import create_app
from ez_kea.core import ha_sync
from ez_kea.routes import system as system_routes
from conftest import login

HA_LIB = "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_ha.so"
LC_LIB = "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so"


def _local_config():
    return {"Dhcp4": {
        "interfaces-config": {"interfaces": ["eth1"]},
        "control-sockets": [{"socket-type": "unix", "socket-name": "/var/run/kea/kea4-ctrl-socket"}],
        "lease-database": {"type": "memfile", "name": "/var/lib/kea/kea-leases4.csv"},
        "subnet4": [{"id": 1, "subnet": "10.0.0.0/24", "pools": [{"pool": "10.0.0.100 - 10.0.0.199"}]}],
        "hooks-libraries": [
            {"library": LC_LIB},
            {"library": HA_LIB, "parameters": {"high-availability": [{
                "this-server-name": "kea1", "mode": "hot-standby",
                "peers": [
                    {"name": "kea1", "url": "http://10.0.0.1:8001/", "role": "primary"},
                    {"name": "kea2", "url": "http://10.0.0.2:8001/", "role": "standby"},
                ],
            }]}},
        ],
    }}


class FakeKea:
    """Kea HTTP control socket: basic auth, config-get/test/set/write/hash-get."""

    def __init__(self, username="ez-kea", password="pw"):
        self.creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.running = {"Dhcp4": {
            "interfaces-config": {"interfaces": ["ens19"]},
            "control-sockets": [
                {"socket-type": "unix", "socket-name": "/var/run/kea/kea4-ctrl-socket"},
                {"socket-type": "http", "socket-address": "127.0.0.1", "socket-port": 0},
            ],
            "lease-database": {"type": "memfile", "name": "/srv/kea2-leases.csv"},
            "subnet4": [],
        }}
        self.written = None
        self.fail_set = False
        self.fail_test = False
        self.commands = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                if self.headers.get("Authorization") != f"Basic {fake.creds}":
                    self.send_response(401)
                    self.end_headers()
                    return
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.commands.append(body["command"])
                out = fake.handle(body["command"], body.get("arguments"))
                raw = json.dumps([out]).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def hash(self):
        return hashlib.sha256(json.dumps(self.running, sort_keys=True).encode()).hexdigest()

    def handle(self, command, args):
        if command == "config-get":
            return {"result": 0, "arguments": {**copy.deepcopy(self.running), "hash": self.hash()}}
        if command == "config-test":
            return {"result": 1, "text": "bad pool"} if self.fail_test else {"result": 0, "text": "sane"}
        if command == "config-set":
            if self.fail_set and args != self.previous_ok:
                return {"result": 5, "text": "One or more hook libraries failed to load"}
            self.running = copy.deepcopy(args)
            return {"result": 0, "arguments": {"hash": self.hash()}}
        if command == "config-write":
            self.written = copy.deepcopy(self.running)
            return {"result": 0, "text": "written"}
        if command == "config-hash-get":
            return {"result": 0, "arguments": {"hash": self.hash()}}
        return {"result": 2, "text": "not supported"}

    def stop(self):
        self.server.shutdown()


@pytest.fixture
def peer():
    fake = FakeKea()
    fake.previous_ok = copy.deepcopy(fake.running)
    yield fake
    fake.stop()


@pytest.fixture
def app(tmp_path, monkeypatch):
    settings_file = tmp_path / "settings.json"
    settings_file.write_text("{}")
    app = create_app(config_overrides={"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path}/test.db"})
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, SETTINGS_FILE=str(settings_file))
    config_file = tmp_path / "kea-dhcp4.conf"
    config_file.write_text(json.dumps(_local_config()))
    app.config["DHCP_CONFIG_FILE"] = str(config_file)
    config_file6 = tmp_path / "kea-dhcp6.conf"
    config_file6.write_text(json.dumps({"Dhcp6": {"subnet6": []}}))
    app.config["DHCP6_CONFIG_FILE"] = str(config_file6)
    # No Kea binary here: the local test and reload are stubbed per test.
    monkeypatch.setattr(system_routes, "_test_config_impl", lambda v: jsonify({"message": "Syntax check passed!"}))
    monkeypatch.setattr(system_routes, "_apply_local", lambda v: jsonify({"message": "KEA service reloaded successfully!"}))
    yield app


@pytest.fixture
def client(app):
    return login(app.test_client(), app)


def _manage(app, peer):
    with app.app_context():
        ha_sync.save_auth("ez-kea", "pw", "")
        ha_sync.save_peer_apis("Dhcp4", {"kea2": {"api-url": peer.url}})


# --- building the peer's config ---------------------------------------------------

def test_push_config_keeps_peer_owned_keys_and_renames_server():
    live = {"Dhcp4": {"interfaces-config": {"interfaces": ["ens19"]},
                      "control-sockets": [{"socket-type": "http", "socket-port": 8000}],
                      "lease-database": {"type": "memfile", "name": "/srv/x.csv"}}, "hash": "abc"}
    out = ha_sync.build_push_config(_local_config(), "Dhcp4", "kea2", live)
    block = out["Dhcp4"]
    assert list(out) == ["Dhcp4"]
    assert block["interfaces-config"] == {"interfaces": ["ens19"]}
    assert block["control-sockets"] == [{"socket-type": "http", "socket-port": 8000}]
    assert block["lease-database"]["name"] == "/srv/x.csv"
    assert block["subnet4"] == _local_config()["Dhcp4"]["subnet4"]
    assert block["hooks-libraries"][1]["parameters"]["high-availability"][0]["this-server-name"] == "kea2"


def test_push_config_drops_local_only_keys_peer_lacks():
    live = {"Dhcp4": {"control-sockets": [{"socket-type": "http"}]}}
    block = ha_sync.build_push_config(_local_config(), "Dhcp4", "kea2", live)["Dhcp4"]
    assert "interfaces-config" not in block  # never send this server's interfaces to the peer
    assert "lease-database" not in block


def test_bootstrap_config_adds_api_socket_with_credential_files():
    cfg = ha_sync.bootstrap_config(_local_config(), "Dhcp4", "kea2", "http://10.0.0.2:8000/")
    socks = cfg["Dhcp4"]["control-sockets"]
    assert socks[0]["socket-type"] == "unix"
    api = socks[1]
    assert (api["socket-type"], api["socket-address"], api["socket-port"]) == ("http", "10.0.0.2", 8000)
    client = api["authentication"]["clients"][0]
    # Kea 3.x refuses clear-text user/password in the config.
    assert client == {"user-file": "ez-kea-api-user", "password-file": "ez-kea-api-password"}
    assert cfg["Dhcp4"]["hooks-libraries"][1]["parameters"]["high-availability"][0]["this-server-name"] == "kea2"


def test_bootstrap_script_installs_and_reloads(app):
    with app.app_context():
        script = ha_sync.bootstrap_script(_local_config(), "Dhcp4", "kea2", "http://10.0.0.2:8000/")
        pw = ha_sync.get_auth()["password"]
    assert script.startswith("#!/bin/sh")
    assert "kea-dhcp4 -t" in script and "isc-kea-dhcp4-server" in script
    assert f"printf '%s' {pw} >" in script and pw.isalnum() and len(pw) == 32
    body = script.split("<<'EZKEA_CONFIG_EOF'\n", 1)[1].split("\nEZKEA_CONFIG_EOF", 1)[0]
    assert json.loads(body)["Dhcp4"]["control-sockets"][-1]["socket-port"] == 8000


# --- form -----------------------------------------------------------------------

def _ha_params():
    return {"this-server-name": "kea1", "peers": [
        {"name": "kea1", "url": "http://10.0.0.1:8001/"}, {"name": "kea2", "url": "http://10.0.0.2:8001/"}]}


@pytest.mark.parametrize("url,ok", [
    ("http://10.0.0.2:8000/", True),
    ("https://10.0.0.2:8443", True),
    ("", True),
    ("http://kea2.lan:8000/", False),
    ("ftp://10.0.0.2:8000/", False),
    ("http://10.0.0.2:8001/", False),  # same port as kea2's HA listener
])
def test_parse_peer_api_urls(url, ok):
    form = MultiDict([("peer-name[]", "kea1"), ("peer-api-url[]", ""), ("peer-name[]", "kea2"), ("peer-api-url[]", url)])
    apis, errors = ha_sync.parse_peer_api_form(form, _ha_params())
    assert (errors == []) is ok, errors
    if ok and url:
        assert apis["kea2"]["api-url"].endswith("/")


def test_api_url_on_this_server_is_refused():
    form = MultiDict([("peer-name[]", "kea1"), ("peer-api-url[]", "http://10.0.0.1:8000/")])
    _, errors = ha_sync.parse_peer_api_form(form, _ha_params())
    assert "this server" in errors[0]


# --- Apply ----------------------------------------------------------------------

def test_apply_without_managed_peers_is_unchanged(client, app):
    r = client.post("/apply-config/4")
    assert r.status_code == 200
    assert "not managed by EZ-KEA" in r.get_json()["message"]
    with app.app_context():
        from ez_kea.models import SystemSetting
        assert SystemSetting.query.get("ha_sync_auth") is None  # no credentials minted for nothing


def test_apply_pushes_and_records_in_sync(client, app, peer):
    _manage(app, peer)
    r = client.post("/apply-config/4")
    assert r.status_code == 200, r.get_json()
    assert "Pushed to HA peer kea2" in r.get_json()["message"]
    assert peer.commands == ["config-get", "config-test", "config-set", "config-write"]
    assert peer.written["Dhcp4"]["subnet4"][0]["subnet"] == "10.0.0.0/24"
    assert peer.written["Dhcp4"]["interfaces-config"] == {"interfaces": ["ens19"]}
    status = client.get("/api/ha-sync-status/4").get_json()["peers"][0]
    assert status["status"] == "in-sync" and status["pushed-at"]


def test_sync_status_tracks_local_and_peer_changes(client, app, peer):
    _manage(app, peer)
    assert client.get("/api/ha-sync-status/4").get_json()["peers"][0]["detail"] == "never pushed from EZ-KEA"
    client.post("/apply-config/4")
    cfg = json.loads(open(app.config["DHCP_CONFIG_FILE"]).read())
    cfg["Dhcp4"]["subnet4"][0]["pools"] = [{"pool": "10.0.0.50 - 10.0.0.60"}]
    open(app.config["DHCP_CONFIG_FILE"], "w").write(json.dumps(cfg))
    assert "this server's config changed" in client.get("/api/ha-sync-status/4").get_json()["peers"][0]["detail"]
    client.post("/apply-config/4")
    peer.running["Dhcp4"]["valid-lifetime"] = 1234
    assert "outside EZ-KEA" in client.get("/api/ha-sync-status/4").get_json()["peers"][0]["detail"]


def test_peer_rejecting_config_applies_nothing(client, app, peer, monkeypatch):
    _manage(app, peer)
    reloaded = []
    monkeypatch.setattr(system_routes, "_apply_local", lambda v: reloaded.append(v) or jsonify({"message": "ok"}))
    peer.fail_test = True
    r = client.post("/apply-config/4")
    assert r.status_code == 409
    assert "Nothing was applied. kea2: rejected the config: bad pool" in r.get_json()["error"]
    assert reloaded == [] and "config-set" not in peer.commands


def test_peer_failing_to_load_is_rolled_back_and_nothing_applied(client, app, peer, monkeypatch):
    _manage(app, peer)
    reloaded = []
    monkeypatch.setattr(system_routes, "_apply_local", lambda v: reloaded.append(v) or jsonify({"message": "ok"}))
    peer.fail_set = True  # config-test passes, config-set fails (as with a missing hook library)
    r = client.post("/apply-config/4")
    assert r.status_code == 409
    err = r.get_json()["error"]
    assert "kea2 could not load the config" in err and "kea2 restored to its previous config" in err
    assert reloaded == []
    assert peer.running == peer.previous_ok
    assert peer.written is None


def test_local_reload_failure_rolls_peers_back(client, app, peer, monkeypatch):
    _manage(app, peer)
    monkeypatch.setattr(system_routes, "_apply_local",
                        lambda v: (jsonify({"error": "Kea refused the reload: boom"}), 500))
    r = client.post("/apply-config/4")
    assert r.status_code == 500
    assert "Kea refused the reload: boom" in r.get_json()["error"]
    assert "kea2 restored to its previous config" in r.get_json()["error"]
    assert peer.running == peer.previous_ok and peer.written is None


def test_unreachable_peer_blocks_until_skipped(client, app, peer, monkeypatch):
    _manage(app, peer)
    peer.stop()
    reloaded = []
    monkeypatch.setattr(system_routes, "_apply_local", lambda v: reloaded.append(v) or jsonify({"message": "ok"}))
    r = client.post("/apply-config/4")
    assert r.status_code == 409 and r.get_json()["peers_unreachable"] == ["kea2"]
    assert reloaded == []
    r = client.post("/apply-config/4?skip_unreachable=1")
    assert r.status_code == 200 and "Not pushed to kea2 (unreachable)" in r.get_json()["message"]
    assert reloaded == ["4"]
    assert client.get("/api/ha-sync-status/4").get_json()["peers"][0]["status"] == "unreachable"


def test_wrong_credentials_are_reported_not_treated_as_unreachable(client, app, peer):
    _manage(app, peer)
    with app.app_context():
        ha_sync.save_auth("ez-kea", "wrong-password-123", "")
    r = client.post("/apply-config/4")
    assert r.status_code == 409
    assert "rejected EZ-KEA's credentials" in r.get_json()["error"]
    assert "peers_unreachable" not in r.get_json()


# --- HA page routes ---------------------------------------------------------------

def test_save_ha_stores_api_url_and_bootstrap_download(client, app):
    data = {
        "ha-enabled": "on", "this-server-name": "kea1", "ha-mode": "hot-standby",
        "heartbeat-delay": "10000", "max-response-delay": "60000", "max-ack-delay": "10000", "max-unacked-clients": "10",
        "peer-name[]": ["kea1", "kea2"], "peer-url[]": ["http://10.0.0.1:8001/", "http://10.0.0.2:8001/"],
        "peer-api-url[]": ["", "http://10.0.0.2:8000/"], "peer-role[]": ["primary", "standby"],
        "peer-autofailover[]": ["yes", "yes"],
    }
    r = client.post("/save-ha-config", data=data, follow_redirects=True)
    assert b"pushes it to kea2" in r.data
    with app.app_context():
        assert ha_sync.get_peer_apis("Dhcp4") == {"kea2": {"api-url": "http://10.0.0.2:8000/"}}
    page = client.get("/high-availability").get_data(as_text=True)
    assert 'value="http://10.0.0.2:8000/"' in page and "One-time setup script" in page
    r = client.get("/high-availability/bootstrap/4/kea2")
    assert r.status_code == 200 and r.headers["Cache-Control"] == "no-store"
    assert "ez-kea-bootstrap-kea2-v4.sh" in r.headers["Content-Disposition"]
    assert client.get("/high-availability/bootstrap/4/kea1").status_code == 404
    assert client.get("/high-availability/bootstrap/9/kea2").status_code == 404


def test_sync_settings_keep_password_when_blank(client, app):
    with app.app_context():
        first = ha_sync.get_auth()["password"]
    client.post("/high-availability/sync-settings", data={"sync-username": "kea-sync", "sync-password": "", "sync-ca-file": ""})
    with app.app_context():
        auth = ha_sync.get_auth()
    assert auth["username"] == "kea-sync" and auth["password"] == first
    r = client.post("/high-availability/sync-settings", data={"sync-username": "x", "sync-password": "short"},
                    follow_redirects=True)
    assert b"at least 12 characters" in r.data
    page = client.get("/high-availability").get_data(as_text=True)
    assert first not in page  # the password is never rendered


def test_bad_tls_certificate_is_an_error_not_an_outage(app, monkeypatch):
    import ssl
    import urllib.error

    def boom(*a, **k):
        raise urllib.error.URLError(ssl.SSLCertVerificationError("certificate verify failed"))

    monkeypatch.setattr(ha_sync.urllib.request, "urlopen", boom)
    with pytest.raises(ha_sync.PeerApiError) as e:
        ha_sync.peer_command("https://10.0.0.2:8443/", {"username": "u", "password": "p"}, "status-get")
    assert not e.value.unreachable and "CA File" in str(e.value)


def test_wrong_credentials_show_as_error_status(client, app, peer):
    _manage(app, peer)
    with app.app_context():
        ha_sync.save_auth("ez-kea", "wrong-password-123", "")
    assert client.get("/api/ha-sync-status/4").get_json()["peers"][0]["status"] == "error"
