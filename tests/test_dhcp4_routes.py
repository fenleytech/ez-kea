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
    # CSRF protection is exercised in test_csrf.py against
    # a real client; these tests POST directly without a token/session, so it's
    # disabled here the same way Flask's own docs recommend for route unit tests.
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SETTINGS_FILE"] = str(settings_file)
    config_file = tmp_path / "kea-dhcp4.conf"
    # Provide a minimal valid config
    config_file.write_text(json.dumps({"Dhcp4": {"shared-networks": []}}))
    app.config["DHCP_CONFIG_FILE"] = str(config_file)
    app.config["DHCP_LEASES_FILE"] = str(tmp_path / "leases.csv")
    # leases()/mac_reservations() ingest inline (see core/state_index.py) --
    # without this override every test in this file would write to the real
    # developer ./data directory instead of this test's own tmp_path.
    app.config["STATE_INDEX_DB"] = str(tmp_path / "stateindex.db")
    yield app

@pytest.fixture
def client(app):
    from conftest import login
    return login(app.test_client(), app)

def test_pools_get(client):
    response = client.get("/pools")
    assert response.status_code == 200

def test_pools_get_with_standalone_subnets(app):
    """Regression test: pools.html referenced a
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
    """Regression test: new_reservation() only ever
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
    """Regression test: posting a reservation for a
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
    """Regression test: new_reservation() never
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
    """Regression test: the hostname 'required'
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
    """Regression test: mac_reservations()'s sort
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
    """Regression test: delete_reservation() only
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


# ── Edit routes ───────────────────────────────────────────────────────────

def _write_shared_network_config(app, network_name="TestNet", subnet="10.0.0.0/24"):
    config_file = app.config["DHCP_CONFIG_FILE"]
    with open(config_file, "w") as f:
        json.dump({
            "Dhcp4": {
                "shared-networks": [{
                    "name": network_name,
                    "subnet4": [{
                        "id": 1, "subnet": subnet,
                        "option-data": [{"name": "routers", "data": "10.0.0.1"}],
                        "pools": [{"pool": "10.0.0.10 - 10.0.0.100"}],
                        "reservations": [],
                    }],
                }],
                "subnet4": [],
            }
        }, f)

def test_edit_shared_network_get_prefills_name(app):
    _write_shared_network_config(app)
    client = login(app.test_client(), app)
    response = client.get("/edit-shared-network?shared-network-name=TestNet")
    assert response.status_code == 200
    assert b"TestNet" in response.data

def test_edit_shared_network_get_not_found_redirects(client):
    response = client.get("/edit-shared-network?shared-network-name=NoSuchNet")
    assert response.status_code == 302

def test_edit_shared_network_post_renames_in_place(app):
    _write_shared_network_config(app)
    client = login(app.test_client(), app)
    response = client.post("/edit-shared-network", data={
        "original-shared-network-name": "TestNet",
        "shared-network-name": "RenamedNet",
    })
    assert response.status_code == 302

    with open(app.config["DHCP_CONFIG_FILE"]) as f:
        config = json.load(f)
    networks = config["Dhcp4"]["shared-networks"]
    assert len(networks) == 1
    assert networks[0]["name"] == "RenamedNet"
    # The subnet nested inside it must survive untouched.
    assert networks[0]["subnet4"][0]["subnet"] == "10.0.0.0/24"

def test_edit_shared_network_post_rejects_collision_with_another_network(app):
    config_file = app.config["DHCP_CONFIG_FILE"]
    with open(config_file, "w") as f:
        json.dump({
            "Dhcp4": {
                "shared-networks": [
                    {"name": "NetA", "subnet4": []},
                    {"name": "NetB", "subnet4": []},
                ],
                "subnet4": [],
            }
        }, f)
    client = login(app.test_client(), app)
    response = client.post("/edit-shared-network", data={
        "original-shared-network-name": "NetA",
        "shared-network-name": "NetB",
    })
    assert response.status_code == 400
    assert b"already exists" in response.data

def test_edit_subnet_get_prefills_existing_values(app):
    _write_shared_network_config(app)
    client = login(app.test_client(), app)
    response = client.get("/edit-subnet?subnet=10.0.0.0/24&shared-network-name=TestNet")
    assert response.status_code == 200
    assert b"10.0.0.1" in response.data  # router
    assert b"10.0.0.10" in response.data  # pool start

def test_edit_subnet_get_not_found_redirects(client):
    response = client.get("/edit-subnet?subnet=10.99.99.0/24")
    assert response.status_code == 302

def test_edit_subnet_post_updates_router_and_pool_in_place(app):
    _write_shared_network_config(app)
    client = login(app.test_client(), app)
    response = client.post("/edit-subnet", data={
        "subnet": "10.0.0.0/24",
        "shared-network-name": "TestNet",
        "routers": "10.0.0.254",
        "range-start": "10.0.0.20",
        "range-end": "10.0.0.90",
    })
    assert response.status_code == 302

    with open(app.config["DHCP_CONFIG_FILE"]) as f:
        config = json.load(f)
    subnet_obj = config["Dhcp4"]["shared-networks"][0]["subnet4"][0]
    assert subnet_obj["option-data"] == [{"name": "routers", "data": "10.0.0.254"}]
    assert subnet_obj["pools"] == [{"pool": "10.0.0.20 - 10.0.0.90"}]
    # Identity/other fields must survive an in-place update.
    assert subnet_obj["subnet"] == "10.0.0.0/24"
    assert subnet_obj["id"] == 1

def test_edit_subnet_post_cannot_change_cidr(app):
    """The subnet form field for CIDR is locked/hidden on edit; even if a
    client POSTs a different value, it's never read as the target CIDR --
    only the identifying 'subnet' field is used to locate the object, and
    the object's own 'subnet' key is left untouched."""
    _write_shared_network_config(app)
    client = login(app.test_client(), app)
    client.post("/edit-subnet", data={
        "subnet": "10.0.0.0/24",
        "shared-network-name": "TestNet",
        "routers": "10.0.0.254",
        "range-start": "10.0.0.20",
        "range-end": "10.0.0.90",
    })
    with open(app.config["DHCP_CONFIG_FILE"]) as f:
        config = json.load(f)
    subnet_obj = config["Dhcp4"]["shared-networks"][0]["subnet4"][0]
    assert subnet_obj["subnet"] == "10.0.0.0/24"

def test_edit_subnet_post_static_only_removes_pools(app):
    _write_shared_network_config(app)
    client = login(app.test_client(), app)
    response = client.post("/edit-subnet", data={
        "subnet": "10.0.0.0/24",
        "shared-network-name": "TestNet",
        "routers": "10.0.0.254",
        "static-only": "on",
    })
    assert response.status_code == 302

    with open(app.config["DHCP_CONFIG_FILE"]) as f:
        config = json.load(f)
    subnet_obj = config["Dhcp4"]["shared-networks"][0]["subnet4"][0]
    assert "pools" not in subnet_obj

def test_edit_subnet_post_invalid_router_returns_form_error(app):
    _write_shared_network_config(app)
    client = login(app.test_client(), app)
    response = client.post("/edit-subnet", data={
        "subnet": "10.0.0.0/24",
        "shared-network-name": "TestNet",
        "routers": "not-an-ip",
        "static-only": "on",
    })
    assert response.status_code == 400
    assert b"Router address" in response.data

def test_edit_reservation_get_prefills_existing_values(app):
    _write_standalone_subnet_config(app)
    client = login(app.test_client(), app)
    client.post("/new-reservation", data={
        "subnet": "192.168.1.0/24",
        "ip-address": "192.168.1.50",
        "hostname": "test-host",
        "mac-address": "00:1A:2B:3C:4D:5E",
    })
    response = client.get("/edit-reservation?hw-address=00:1A:2B:3C:4D:5E&subnet=192.168.1.0/24")
    assert response.status_code == 200
    assert b"192.168.1.50" in response.data
    assert b"test-host" in response.data

def test_edit_reservation_get_not_found_redirects(client):
    response = client.get("/edit-reservation?hw-address=00:00:00:00:00:00&subnet=192.168.1.0/24")
    assert response.status_code == 302

def test_edit_reservation_post_updates_in_place(app):
    _write_standalone_subnet_config(app)
    client = login(app.test_client(), app)
    client.post("/new-reservation", data={
        "subnet": "192.168.1.0/24",
        "ip-address": "192.168.1.50",
        "hostname": "test-host",
        "mac-address": "00:1A:2B:3C:4D:5E",
    })
    response = client.post("/edit-reservation", data={
        "hw-address": "00:1A:2B:3C:4D:5E",  # original identity
        "subnet": "192.168.1.0/24",
        "mac-address": "00:1A:2B:3C:4D:5F",  # typo fix
        "hostname": "renamed-host",
        "ip-address": "192.168.1.51",
    })
    assert response.status_code == 302

    with open(app.config["DHCP_CONFIG_FILE"]) as f:
        config = json.load(f)
    reservations = config["Dhcp4"]["subnet4"][0]["reservations"]
    assert len(reservations) == 1
    assert reservations[0]["hw-address"] == "00:1A:2B:3C:4D:5F"
    assert reservations[0]["hostname"] == "renamed-host"
    assert reservations[0]["ip-address"] == "192.168.1.51"

def test_edit_reservation_post_mac_collision_with_another_reservation_rejected(app):
    config_file = app.config["DHCP_CONFIG_FILE"]
    with open(config_file, "w") as f:
        json.dump({
            "Dhcp4": {
                "shared-networks": [],
                "subnet4": [{
                    "id": 1, "subnet": "192.168.1.0/24",
                    "reservations": [
                        {"hw-address": "00:1A:2B:3C:4D:5E", "ip-address": "192.168.1.50", "hostname": "one"},
                        {"hw-address": "00:1A:2B:3C:4D:5F", "ip-address": "192.168.1.51", "hostname": "two"},
                    ],
                }],
            }
        }, f)
    client = login(app.test_client(), app)
    response = client.post("/edit-reservation", data={
        "hw-address": "00:1A:2B:3C:4D:5E",
        "subnet": "192.168.1.0/24",
        "mac-address": "00:1A:2B:3C:4D:5F",  # collides with the other reservation
        "hostname": "one",
        "ip-address": "192.168.1.50",
    })
    assert response.status_code == 400
    assert b"already exists" in response.data

    with open(config_file) as f:
        config = json.load(f)
    reservations = config["Dhcp4"]["subnet4"][0]["reservations"]
    assert reservations[0]["hw-address"] == "00:1A:2B:3C:4D:5E"  # unchanged
