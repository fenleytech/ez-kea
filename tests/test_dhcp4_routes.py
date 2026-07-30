# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import json
from conftest import login
import pytest
from flask import Flask
from unittest.mock import patch
from ez_kea import create_app

@pytest.fixture
def app(tmp_path):
    # Pass a valid settings file to avoid discovery overriding defaults erroneously
    settings_file = tmp_path / "settings.json"
    settings_file.write_text("{}")
    
    app = create_app(config_overrides={
        # Auth's own user DB lives here per test — never the real dev database
        # (db.create_all()/_seed_admin() run eagerly inside create_app(), so
        # this must be set before it's called, not patched on afterward).
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path}/test.db",
    })
    app.config["TESTING"] = True
    # CSRF protection (AUDIT_FINDINGS.md 1.4) is exercised in test_csrf.py against
    # a real client; these tests POST directly without a token/session, so it's
    # disabled here the same way Flask's own docs recommend for route unit tests.
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SETTINGS_FILE"] = str(settings_file)
    config_file = tmp_path / "kea-dhcp4.conf"
    # Provide a minimal valid config
    config_file.write_text(json.dumps({"Dhcp4": {"shared-networks": []}}))
    app.config["DHCP_CONFIG_FILE"] = str(config_file)
    app.config["DHCP_LEASES_FILE"] = str(tmp_path / "leases.csv")
    yield app

@pytest.fixture
def client(app):
    from conftest import login
    return login(app.test_client(), app)

def test_pools_get(client):
    response = client.get("/pools")
    assert response.status_code == 200

def test_pools_get_with_standalone_subnets(app):
    """Regression test for AUDIT_FINDINGS 2.1: pools.html referenced a
    nonexistent endpoint name for standalone-subnet Options links, which made
    url_for() raise a BuildError and 500 the whole /pools page as soon as any
    standalone subnet existed."""
    config_file = app.config["DHCP_CONFIG_FILE"]
    with open(config_file, "w") as f:
        json.dump({
            "Dhcp4": {
                "shared-networks": [],
                "subnet4": [
                    {"id": 1, "subnet": "192.168.1.0/24", "pools": [{"pool": "192.168.1.10 - 192.168.1.100"}]}
                ]
            }
        }, f)

    client = login(app.test_client(), app)
    response = client.get("/pools")
    assert response.status_code == 200
    assert b"192.168.1.0/24" in response.data

def test_new_shared_network_post(client):
    response = client.post("/new-shared-network", data={"shared-network-name": "TestNet"})
    assert response.status_code == 302 # Redirects to pools
    
def test_delete_shared_network_post(client):
    response = client.post("/delete-shared-network", data={"shared-network-name": "TestNet"})
    assert response.status_code == 302 # Redirects to pools

@patch("ez_kea.routes.dhcp4.has_overlap")
def test_new_subnet_post(mock_overlap, client):
    mock_overlap.return_value = False
    data = {
        "subnet": "192.168.1.0/24",
        "routers": "192.168.1.1",
        "static-only": "on"
    }
    response = client.post("/new-subnet", data=data)
    assert response.status_code == 302

def test_delete_subnet_post(client):
    response = client.post("/delete-subnet", data={"subnet": "192.168.1.0/24"})
    assert response.status_code == 302

def test_mac_reservations_get(client):
    response = client.get("/mac-reservations")
    assert response.status_code == 200

def test_leases_get(client):
    # Depending on validation and leases file, this might throw if file doesn't exist but we catch it in get_active_leases
    response = client.get("/leases")
    assert response.status_code == 200

def _write_standalone_subnet_config(app):
    config_file = app.config["DHCP_CONFIG_FILE"]
    with open(config_file, "w") as f:
        json.dump({
            "Dhcp4": {
                "shared-networks": [],
                "subnet4": [
                    {"id": 1, "subnet": "192.168.1.0/24", "pools": [{"pool": "192.168.1.10 - 192.168.1.100"}], "reservations": []}
                ]
            }
        }, f)

def test_new_reservation_on_standalone_subnet_succeeds(app):
    """Regression test for AUDIT_FINDINGS 2.2: new_reservation() only ever
    walked Dhcp4.shared-networks[].subnet4[], so reservations posted against
    a standalone subnet were silently dropped (HTTP 302 'success', nothing
    written). Confirm the reservation is now actually persisted."""
    _write_standalone_subnet_config(app)
    client = login(app.test_client(), app)
    data = {
        "subnet": "192.168.1.0/24",
        "ip-address": "192.168.1.50",
        "hostname": "test-host",
        "mac-address": "00:1A:2B:3C:4D:5E",
    }
    response = client.post("/new-reservation", data=data)
    assert response.status_code == 302

    with open(app.config["DHCP_CONFIG_FILE"]) as f:
        config = json.load(f)
    reservations = config["Dhcp4"]["subnet4"][0]["reservations"]
    assert len(reservations) == 1
    assert reservations[0]["ip-address"] == "192.168.1.50"
    assert reservations[0]["hw-address"] == "00:1A:2B:3C:4D:5E"

def test_new_reservation_unknown_subnet_returns_form_error(client):
    """Regression test for AUDIT_FINDINGS 2.2: posting a reservation for a
    subnet that doesn't match any known subnet (standalone or shared) used
    to silently 302 with nothing written. It should now return a form
    error instead."""
    data = {
        "subnet": "10.99.99.0/24",  # does not exist anywhere in config
        "ip-address": "10.99.99.50",
        "hostname": "test-host",
        "mac-address": "00:1A:2B:3C:4D:5E",
    }
    response = client.post("/new-reservation", data=data)
    assert response.status_code == 400
    assert b"not found" in response.data.lower()

def test_new_reservation_invalid_ip_address_returns_form_error(app):
    """Regression test for AUDIT_FINDINGS 2.4: new_reservation() never
    validated that ip-address was a real IPv4 address, so a malformed value
    could be saved through the app's own form and later crash
    /mac-reservations. Should now be rejected at submission time."""
    _write_standalone_subnet_config(app)
    client = login(app.test_client(), app)
    data = {
        "subnet": "192.168.1.0/24",
        "ip-address": "not-an-ip-address",
        "hostname": "test-host",
        "mac-address": "00:1A:2B:3C:4D:5E",
    }
    response = client.post("/new-reservation", data=data)
    assert response.status_code == 400
    assert b"Invalid IPv4 address" in response.data

    with open(app.config["DHCP_CONFIG_FILE"]) as f:
        config = json.load(f)
    assert config["Dhcp4"]["subnet4"][0]["reservations"] == []

def test_new_reservation_all_emoji_hostname_rejected(app):
    """Regression test for AUDIT_FINDINGS 2.7: the hostname 'required'
    check used to run on the raw value before sanitize_hostname() stripped
    it, so an all-emoji hostname passed the non-empty check and then
    silently sanitized down to an empty string. It should now be rejected."""
    _write_standalone_subnet_config(app)
    client = login(app.test_client(), app)
    data = {
        "subnet": "192.168.1.0/24",
        "ip-address": "192.168.1.50",
        "hostname": "\U0001F600\U0001F525\U0001F389",  # emoji only
        "mac-address": "00:1A:2B:3C:4D:5E",
    }
    response = client.post("/new-reservation", data=data)
    assert response.status_code == 400
    assert b"Hostname is required" in response.data

def test_mac_reservations_survives_malformed_ip_address(app):
    """Regression test for AUDIT_FINDINGS 2.4: mac_reservations()'s sort
    key crashed on a non-IPv4 ip-address already present in a config
    (e.g. hand-edited or from an older buggy save). The page must not
    500 even if a bad value is already on disk."""
    config_file = app.config["DHCP_CONFIG_FILE"]
    with open(config_file, "w") as f:
        json.dump({
            "Dhcp4": {
                "shared-networks": [],
                "subnet4": [
                    {
                        "id": 1,
                        "subnet": "192.168.1.0/24",
                        "reservations": [
                            {"hw-address": "00:1A:2B:3C:4D:5E", "ip-address": "not-an-ip-address", "hostname": "bad"},
                            {"hw-address": "00:1A:2B:3C:4D:5F", "ip-address": "192.168.1.20", "hostname": "good"},
                        ],
                    }
                ],
            }
        }, f)

    client = login(app.test_client(), app)
    response = client.get("/mac-reservations")
    assert response.status_code == 200
    assert b"not-an-ip-address" in response.data
    assert b"192.168.1.20" in response.data

def test_delete_reservation_on_standalone_subnet(app):
    """Regression test for AUDIT_FINDINGS 2.2: delete_reservation() only
    ever walked shared-networks, so it could never remove a reservation
    living on a standalone subnet."""
    config_file = app.config["DHCP_CONFIG_FILE"]
    with open(config_file, "w") as f:
        json.dump({
            "Dhcp4": {
                "shared-networks": [],
                "subnet4": [
                    {
                        "id": 1,
                        "subnet": "192.168.1.0/24",
                        "reservations": [
                            {"hw-address": "00:1A:2B:3C:4D:5E", "ip-address": "192.168.1.20", "hostname": "good"},
                        ],
                    }
                ],
            }
        }, f)

    client = login(app.test_client(), app)
    response = client.post("/delete-reservation", data={
        "subnet": "192.168.1.0/24",
        "shared-network-name": "",
        "hw-address": "00:1A:2B:3C:4D:5E",
    })
    assert response.status_code == 302

    with open(config_file) as f:
        config = json.load(f)
    assert config["Dhcp4"]["subnet4"][0]["reservations"] == []
