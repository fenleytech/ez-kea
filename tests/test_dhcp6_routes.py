# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import json
import pytest
from flask import Flask
from unittest.mock import patch
from ez_kea import create_app
from conftest import login

@pytest.fixture
def app(tmp_path):
    settings_file = tmp_path / "settings.json"
    settings_file.write_text("{}")
    
    app = create_app(config_overrides={
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path}/test.db",
    })
    app.config["TESTING"] = True
    # CSRF protection is exercised in test_csrf.py against
    # a real client; these tests POST directly without a token/session, so it's
    # disabled here the same way Flask's own docs recommend for route unit tests.
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SETTINGS_FILE"] = str(settings_file)
    config_file = tmp_path / "kea-dhcp6.conf"
    config_file.write_text(json.dumps({"Dhcp6": {"shared-networks": []}}))
    app.config["DHCP6_CONFIG_FILE"] = str(config_file)
    app.config["DHCP6_LEASES_FILE"] = str(tmp_path / "leases6.csv")
    # leases6()/reservations6() ingest inline (see core/state_index.py) --
    # without this override every test in this file would write to the real
    # developer ./data directory instead of this test's own tmp_path.
    app.config["STATE_INDEX_DB"] = str(tmp_path / "stateindex.db")
    yield app

@pytest.fixture
def client(app):
    from conftest import login
    return login(app.test_client(), app)

def test_pools6_get(client):
    response = client.get("/pools6")
    assert response.status_code == 200

def test_pools6_config_buttons_target_v6_routes(client):
    """Regression test for the confirmed bug where the DHCPv6 pools page's
    shared config_buttons.html include always pointed Test/Apply/Backup/
    Restore at the v4 daemon regardless of which page included it."""
    response = client.get("/pools6")
    assert b"/test-config/6" in response.data
    assert b"/apply-config/6" in response.data
    assert b"/backup-config/6" in response.data
    assert b"/restore-config/6" in response.data
    # And must NOT silently point at the bare v4 aliases.
    assert b'"/test-config"' not in response.data
    assert b'"/apply-config"' not in response.data

def test_new_shared_network6_post(client):
    response = client.post("/new-shared-network6", data={"shared-network-name": "TestNet6"})
    assert response.status_code == 302

def test_delete_shared_network6_post(client):
    response = client.post("/delete-shared-network6", data={"shared-network-name": "TestNet6"})
    assert response.status_code == 302

@patch("ez_kea.routes.dhcp6.has_overlap")
def test_new_subnet6_post(mock_overlap, client):
    mock_overlap.return_value = False
    data = {
        "subnet": "2001:db8::/64",
        "shared-network-name": "TestNet6"
    }
    response = client.post("/new-subnet6", data=data)
    # The route returns 302. If error, returns 400.
    assert response.status_code == 302

def test_delete_subnet6_post(client):
    response = client.post("/delete-subnet6", data={"subnet": "2001:db8::/64"})
    assert response.status_code == 302

@patch("ez_kea.routes.dhcp6.has_overlap")
def test_new_subnet6_auto_creates_missing_shared_network(mock_overlap, app):
    """Regression test: new_subnet6() had no else
    branch, so if shared_network_name didn't match any existing shared
    network, save_json()+redirect() still fired as if it succeeded but
    nothing was ever written. Unlike v4's new_subnet(), it should
    auto-create the shared network instead of silently dropping the
    subnet."""
    mock_overlap.return_value = False
    client = login(app.test_client(), app)
    response = client.post("/new-subnet6", data={
        "subnet": "2001:db8:1::/64",
        "shared-network-name": "BrandNewNetwork",
    })
    assert response.status_code == 302

    import json
    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    networks = config["Dhcp6"]["shared-networks"]
    matching = [n for n in networks if n.get("name") == "BrandNewNetwork"]
    assert len(matching) == 1
    assert matching[0]["subnet6"][0]["subnet"] == "2001:db8:1::/64"

@patch("ez_kea.routes.dhcp6.has_overlap")
def test_new_subnet6_without_a_shared_network_name_is_kept_as_standalone(mock_overlap, app, client):
    """
    Regression test: an omitted shared-network-name used to silently drop the
    subnet. It was then made a hard form error, which fixed the data loss but
    left standalone subnets unrepresentable from the UI even though Kea (and
    ISC's own example config) writes plain servers that way.

    The subnet must survive either way -- now as a top-level Dhcp6.subnet6[].
    """
    mock_overlap.return_value = False
    response = client.post("/new-subnet6", data={"subnet": "2001:db8:2::/64"})
    assert response.status_code == 302

    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        dhcp6 = json.load(f)["Dhcp6"]
    assert [s["subnet"] for s in dhcp6.get("subnet6", [])] == ["2001:db8:2::/64"]
    assert not any(n.get("name") == "" for n in dhcp6.get("shared-networks", []))

@patch("ez_kea.routes.dhcp6.has_overlap")
def test_new_subnet6_pd_length_out_of_range_rejected(mock_overlap, client):
    """Regression test: delegated-len only checked
    .isdigit(), so out-of-range values like 0 or 999999 were accepted, and
    a negative value produced a misleading 'required' error."""
    mock_overlap.return_value = False
    response = client.post("/new-subnet6", data={
        "subnet": "2001:db8:3::/64",
        "shared-network-name": "TestNet6",
        "pd-pool": "2001:db8:3::/48",
        "pd-length": "999999",
    })
    assert response.status_code == 400
    assert b"must be between 1 and 128" in response.data

@patch("ez_kea.routes.dhcp6.has_overlap")
def test_new_subnet6_pd_length_negative_gives_correct_error(mock_overlap, client):
    """A negative PD length was supplied but used to produce a misleading
    'is required' message. It should now say it must be in range."""
    mock_overlap.return_value = False
    response = client.post("/new-subnet6", data={
        "subnet": "2001:db8:4::/64",
        "shared-network-name": "TestNet6",
        "pd-pool": "2001:db8:4::/48",
        "pd-length": "-5",
    })
    assert response.status_code == 400
    assert b"is required" not in response.data
    assert b"must be between 1 and 128" in response.data

@patch("ez_kea.routes.dhcp6.has_overlap")
def test_new_subnet6_pd_length_shorter_than_pool_prefix_rejected(mock_overlap, client):
    """Delegated length shorter (numerically smaller prefix, i.e. a bigger
    block) than the PD pool's own prefix length doesn't make sense — Kea
    would reject it."""
    mock_overlap.return_value = False
    response = client.post("/new-subnet6", data={
        "subnet": "2001:db8:5::/64",
        "shared-network-name": "TestNet6",
        "pd-pool": "2001:db8:5::/48",
        "pd-length": "40",
    })
    assert response.status_code == 400
    assert b"greater than or equal to" in response.data


# ── Phase 3: standard IA_NA address pools + subnet6 id ──────────────────────

@patch("ez_kea.routes.dhcp6.has_overlap")
def test_new_subnet6_with_na_pool_post(mock_overlap, app):
    mock_overlap.return_value = False
    client = login(app.test_client(), app)
    response = client.post("/new-subnet6", data={
        "subnet": "2001:db8:6::/64",
        "shared-network-name": "TestNet6",
        "pool-start": "2001:db8:6::100",
        "pool-end": "2001:db8:6::1ff",
    })
    assert response.status_code == 302

    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    networks = config["Dhcp6"]["shared-networks"]
    matching = [n for n in networks if n.get("name") == "TestNet6"]
    assert len(matching) == 1
    subnet_obj = matching[0]["subnet6"][0]
    assert subnet_obj["pools"] == [{"pool": "2001:db8:6::100 - 2001:db8:6::1ff"}]

@patch("ez_kea.routes.dhcp6.has_overlap")
def test_new_subnet6_id_assigned(mock_overlap, app):
    mock_overlap.return_value = False
    client = login(app.test_client(), app)
    client.post("/new-subnet6", data={
        "subnet": "2001:db8:7::/64",
        "shared-network-name": "TestNet6",
    })
    client.post("/new-subnet6", data={
        "subnet": "2001:db8:8::/64",
        "shared-network-name": "TestNet6",
    })

    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    subnets = config["Dhcp6"]["shared-networks"][0]["subnet6"]
    ids = [s["id"] for s in subnets]
    assert ids == [1, 2]

@patch("ez_kea.routes.dhcp6.has_overlap")
def test_new_subnet6_invalid_na_pool_range_rejected(mock_overlap, client):
    mock_overlap.return_value = False
    response = client.post("/new-subnet6", data={
        "subnet": "2001:db8:9::/64",
        "shared-network-name": "TestNet6",
        "pool-start": "2001:db9:9::100",  # outside the subnet
        "pool-end": "2001:db8:9::1ff",
    })
    assert response.status_code == 400
    assert b"Invalid IPv6 address pool range" in response.data

@patch("ez_kea.routes.dhcp6.has_overlap")
def test_new_subnet6_na_and_pd_pools_coexist(mock_overlap, app):
    mock_overlap.return_value = False
    client = login(app.test_client(), app)
    response = client.post("/new-subnet6", data={
        "subnet": "2001:db8:a::/64",
        "shared-network-name": "TestNet6",
        "pool-start": "2001:db8:a::100",
        "pool-end": "2001:db8:a::1ff",
        "pd-pool": "2001:db8:a::/48",
        "pd-length": "64",
    })
    assert response.status_code == 302

    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    subnet_obj = config["Dhcp6"]["shared-networks"][0]["subnet6"][0]
    assert "pools" in subnet_obj
    assert subnet_obj["pd-pools"] == [{
        "prefix": "2001:db8:a::",
        "prefix-len": 48,
        "delegated-len": 64,
    }]


def test_new_subnet6_against_missing_config_stays_dhcp6_rooted(app, client):
    """
    Regression test for a critical bug: new_subnet6() called load_json()
    without passing the v6 default skeleton, so on a config file that
    doesn't parse (or, as here, doesn't exist yet) it silently fell back to
    the v4 skeleton. In a real session this produced a kea-dhcp6.conf file
    with a stray top-level "Dhcp4" block (carrying an unrelated v4 subnet
    from an earlier, unrelated request) alongside "Dhcp6" -- which Kea's own
    parser rejected outright with "expecting Dhcp6". See AUDIT_FINDINGS.md,
    2026-08-02.
    """
    import os
    os.remove(app.config["DHCP6_CONFIG_FILE"])

    response = client.post("/new-subnet6", data={"subnet": "2001:db8:c::/64"})
    assert response.status_code == 302

    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        written = json.load(f)
    assert "Dhcp4" not in written
    assert written["Dhcp6"]["subnet6"][0]["subnet"] == "2001:db8:c::/64"


# ── Phase 4: DUID-based reservations ─────────────────────────────────────────

def _seed_standalone_subnet6(app, subnet="2001:db8:aa::/64"):
    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    config.setdefault("Dhcp6", {}).setdefault("subnet6", []).append({
        "id": 1, "subnet": subnet, "reservations": []
    })
    with open(app.config["DHCP6_CONFIG_FILE"], "w") as f:
        json.dump(config, f)

def test_reservations6_get(client):
    response = client.get("/reservations6")
    assert response.status_code == 200

def test_new_reservation6_na_post(app):
    _seed_standalone_subnet6(app)
    client = login(app.test_client(), app)
    response = client.post("/new-reservation6", data={
        "subnet": "2001:db8:aa::/64",
        "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
        "hostname": "laptop-01",
        "ip-address": "2001:db8:aa::50",
    })
    assert response.status_code == 302

    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    reservations = config["Dhcp6"]["subnet6"][0]["reservations"]
    assert len(reservations) == 1
    assert reservations[0]["ip-addresses"] == ["2001:db8:aa::50"]
    assert reservations[0]["duid"] == "00:03:00:01:aa:bb:cc:dd:ee:ff"

def test_new_reservation6_pd_post(app):
    _seed_standalone_subnet6(app)
    client = login(app.test_client(), app)
    response = client.post("/new-reservation6", data={
        "subnet": "2001:db8:aa::/64",
        "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
        "hostname": "router-01",
        "prefix": "2001:db8:bb::/56",
    })
    assert response.status_code == 302

    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    reservations = config["Dhcp6"]["subnet6"][0]["reservations"]
    assert reservations[0]["prefixes"] == ["2001:db8:bb::/56"]

def test_new_reservation6_invalid_duid_rejected(app):
    _seed_standalone_subnet6(app)
    client = login(app.test_client(), app)
    response = client.post("/new-reservation6", data={
        "subnet": "2001:db8:aa::/64",
        "duid": "not-a-duid",
        "hostname": "laptop-01",
        "ip-address": "2001:db8:aa::50",
    })
    assert response.status_code == 400
    assert b"Invalid DUID format" in response.data

def test_new_reservation6_missing_address_and_prefix_rejected(app):
    _seed_standalone_subnet6(app)
    client = login(app.test_client(), app)
    response = client.post("/new-reservation6", data={
        "subnet": "2001:db8:aa::/64",
        "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
        "hostname": "laptop-01",
    })
    assert response.status_code == 400
    assert b"Either an IPv6 address or a delegated prefix is required" in response.data

def test_delete_reservation6_post(app):
    _seed_standalone_subnet6(app)
    client = login(app.test_client(), app)
    client.post("/new-reservation6", data={
        "subnet": "2001:db8:aa::/64",
        "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
        "hostname": "laptop-01",
        "ip-address": "2001:db8:aa::50",
    })

    response = client.post("/delete-reservation6", data={
        "subnet": "2001:db8:aa::/64",
        "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
    })
    assert response.status_code == 302

    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    assert config["Dhcp6"]["subnet6"][0]["reservations"] == []


# ── Phase 5: subnet6 option-data management (real HTTP routes) ──────────────

def _seed_shared_network6_subnet(app, network_name="OptNet6", subnet="2001:db8:cc::/64"):
    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    config["Dhcp6"]["shared-networks"].append({
        "name": network_name,
        "subnet6": [{"id": 1, "subnet": subnet, "reservations": []}],
    })
    with open(app.config["DHCP6_CONFIG_FILE"], "w") as f:
        json.dump(config, f)

def test_manage_subnet6_options_get(app):
    _seed_shared_network6_subnet(app)
    client = login(app.test_client(), app)
    response = client.get("/options/subnet6/OptNet6/2001:db8:cc::/64")
    assert response.status_code == 200

def test_manage_subnet6_options_post_sets_option(app):
    _seed_shared_network6_subnet(app)
    client = login(app.test_client(), app)
    response = client.post("/options/subnet6/OptNet6/2001:db8:cc::/64", data={
        "option-name": "dns-servers",
        "option-data": "2001:4860:4860::8888",
    })
    assert response.status_code == 302

    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    subnet = config["Dhcp6"]["shared-networks"][0]["subnet6"][0]
    assert subnet["option-data"] == [{"name": "dns-servers", "data": "2001:4860:4860::8888"}]

def test_delete_subnet6_option(app):
    _seed_shared_network6_subnet(app)
    client = login(app.test_client(), app)
    client.post("/options/subnet6/OptNet6/2001:db8:cc::/64", data={
        "option-name": "dns-servers",
        "option-data": "2001:4860:4860::8888",
    })
    response = client.post("/options/subnet6/OptNet6/2001:db8:cc::/64/delete", data={
        "option-name": "dns-servers",
    })
    assert response.status_code == 302

    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    subnet = config["Dhcp6"]["shared-networks"][0]["subnet6"][0]
    assert subnet["option-data"] == []

def test_manage_subnet6_options_not_found(client):
    response = client.get("/options/subnet6/NoSuchNet/2001:db8:zz::/64")
    assert response.status_code == 404

def test_manage_standalone_subnet6_options_post_sets_option(app):
    _seed_standalone_subnet6(app, subnet="2001:db8:dd::/64")
    client = login(app.test_client(), app)
    response = client.post("/options/subnet6/standalone/2001:db8:dd::/64", data={
        "option-name": "domain-search",
        "option-data": "home.local",
    })
    assert response.status_code == 302

    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    subnet = config["Dhcp6"]["subnet6"][0]
    assert subnet["option-data"] == [{"name": "domain-search", "data": "home.local"}]

def test_delete_standalone_subnet6_option(app):
    _seed_standalone_subnet6(app, subnet="2001:db8:ee::/64")
    client = login(app.test_client(), app)
    client.post("/options/subnet6/standalone/2001:db8:ee::/64", data={
        "option-name": "domain-search",
        "option-data": "home.local",
    })
    response = client.post("/options/subnet6/standalone/2001:db8:ee::/64/delete", data={
        "option-name": "domain-search",
    })
    assert response.status_code == 302

    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    assert config["Dhcp6"]["subnet6"][0]["option-data"] == []

def test_leases6_get(client):
    response = client.get("/leases6")
    assert response.status_code == 200

def test_leases6_get_renders_seeded_lease(app):
    import csv as csv_module
    fieldnames = ["address", "duid", "valid_lifetime", "expire", "subnet_id",
                  "pref_lifetime", "lease_type", "iaid", "prefix_len",
                  "fqdn_fwd", "fqdn_rev", "hostname"]
    with open(app.config["DHCP6_LEASES_FILE"], "w", newline="") as f:
        writer = csv_module.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        row = {k: "" for k in fieldnames}
        row.update({
            "address": "2001:db8::50", "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
            "expire": "9999999999", "lease_type": "0", "hostname": "workstation-1",
        })
        writer.writerow(row)

    client = login(app.test_client(), app)
    response = client.get("/leases6")
    assert response.status_code == 200
    assert b"2001:db8::50" in response.data
    assert b"workstation-1" in response.data

def test_manage_standalone_subnet6_options_rejects_shared_network_nested_subnet(app):
    """A subnet that lives inside a shared-network must not be reachable
    through the standalone-only endpoint — that would let option edits
    silently target the wrong subnet object if two subnets share a CIDR
    string across scopes (defense in depth for _find_subnet6 usage)."""
    _seed_shared_network6_subnet(app, subnet="2001:db8:ff::/64")
    client = login(app.test_client(), app)
    response = client.get("/options/subnet6/standalone/2001:db8:ff::/64")
    assert response.status_code == 404


# ── Standalone (non-shared-network) subnet6 ──────────────────────────────────
# Kea writes plain single-subnet setups as a top-level Dhcp6.subnet6[] -- ISC's
# own example config does exactly that. The pools6 view used to read only
# shared-networks, so a live server configured that way rendered as "No IPv6
# Shared Networks Configured" and its subnets were invisible and unmanageable.

def _write_v6_config(app, dhcp6):
    with open(app.config["DHCP6_CONFIG_FILE"], "w") as f:
        json.dump({"Dhcp6": dhcp6}, f)


def _read_v6_config(app):
    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        return json.load(f)["Dhcp6"]


def test_pools6_lists_standalone_subnets(app, client):
    _write_v6_config(app, {
        "shared-networks": [],
        "subnet6": [{
            "id": 1,
            "subnet": "2001:db8:66:10::/64",
            "pools": [{"pool": "2001:db8:66:10::100 - 2001:db8:66:10::200"}],
            "pd-pools": [{"prefix": "2001:db8:66:2000::", "prefix-len": 48, "delegated-len": 64}],
        }],
    })

    body = client.get("/pools6").get_data(as_text=True)

    assert "2001:db8:66:10::/64" in body
    assert "2001:db8:66:10::100 - 2001:db8:66:10::200" in body, "its address pool should show"
    assert "2001:db8:66:2000::" in body, "its PD pool should show"
    assert "No IPv6 Shared Networks Configured" not in body, \
        "a server with a standalone subnet is not an empty server"


def test_pools6_empty_state_only_when_truly_empty(app, client):
    _write_v6_config(app, {"shared-networks": [], "subnet6": []})
    assert "No IPv6 Shared Networks Configured" in client.get("/pools6").get_data(as_text=True)


def test_new_subnet6_without_a_group_creates_a_standalone_subnet(app, client):
    """A blank shared-network-name used to create a shared network named ""."""
    _write_v6_config(app, {"shared-networks": []})

    client.post("/new-subnet6", data={
        "subnet": "2001:db8:99::/64",
        "shared-network-name": "",
        "pool-start": "2001:db8:99::10",
        "pool-end": "2001:db8:99::20",
    })

    dhcp6 = _read_v6_config(app)
    assert [s["subnet"] for s in dhcp6.get("subnet6", [])] == ["2001:db8:99::/64"]
    assert not any(n.get("name") == "" for n in dhcp6.get("shared-networks", [])), \
        "must not invent a shared network with an empty name"


def test_delete_subnet6_removes_a_standalone_subnet(app, client):
    """The delete button on a standalone subnet used to silently do nothing."""
    _write_v6_config(app, {
        "shared-networks": [],
        "subnet6": [
            {"id": 1, "subnet": "2001:db8:66:10::/64"},
            {"id": 2, "subnet": "2001:db8:66:11::/64"},
        ],
    })

    client.post("/delete-subnet6", data={"shared-network-name": "", "subnet": "2001:db8:66:10::/64"})

    assert [s["subnet"] for s in _read_v6_config(app)["subnet6"]] == ["2001:db8:66:11::/64"]


def test_deleting_a_grouped_subnet_leaves_standalone_ones_alone(app, client):
    """The two code paths must not reach into each other."""
    _write_v6_config(app, {
        "shared-networks": [{"name": "vlan20", "subnet6": [{"id": 2, "subnet": "2001:db8:66:20::/64"}]}],
        "subnet6": [{"id": 1, "subnet": "2001:db8:66:10::/64"}],
    })

    client.post("/delete-subnet6", data={"shared-network-name": "vlan20", "subnet": "2001:db8:66:20::/64"})

    dhcp6 = _read_v6_config(app)
    assert dhcp6["shared-networks"][0]["subnet6"] == []
    assert [s["subnet"] for s in dhcp6["subnet6"]] == ["2001:db8:66:10::/64"], \
        "the standalone subnet must be untouched"


# ── Edit routes ───────────────────────────────────────────────────────────

def _write_shared_network6_config(app, network_name="TestNet6", subnet="2001:db8:50::/64"):
    _write_v6_config(app, {
        "shared-networks": [{
            "name": network_name,
            "subnet6": [{
                "id": 1, "subnet": subnet,
                "pools": [{"pool": "2001:db8:50::100 - 2001:db8:50::1ff"}],
                "reservations": [],
            }],
        }],
        "subnet6": [],
    })

def test_edit_shared_network6_get_prefills_name(app, client):
    _write_shared_network6_config(app)
    response = client.get("/edit-shared-network6?shared-network-name=TestNet6")
    assert response.status_code == 200
    assert b"TestNet6" in response.data

def test_edit_shared_network6_get_not_found_redirects(client):
    response = client.get("/edit-shared-network6?shared-network-name=NoSuchNet6")
    assert response.status_code == 302

def test_edit_shared_network6_post_renames_in_place(app, client):
    _write_shared_network6_config(app)
    response = client.post("/edit-shared-network6", data={
        "original-shared-network-name": "TestNet6",
        "shared-network-name": "RenamedNet6",
    })
    assert response.status_code == 302

    dhcp6 = _read_v6_config(app)
    networks = dhcp6["shared-networks"]
    assert len(networks) == 1
    assert networks[0]["name"] == "RenamedNet6"
    assert networks[0]["subnet6"][0]["subnet"] == "2001:db8:50::/64"

def test_edit_shared_network6_post_rejects_collision_with_another_network(app, client):
    _write_v6_config(app, {
        "shared-networks": [
            {"name": "NetA6", "subnet6": []},
            {"name": "NetB6", "subnet6": []},
        ],
        "subnet6": [],
    })
    response = client.post("/edit-shared-network6", data={
        "original-shared-network-name": "NetA6",
        "shared-network-name": "NetB6",
    })
    assert response.status_code == 400
    assert b"already exists" in response.data

def test_edit_subnet6_get_prefills_existing_values(app, client):
    _write_shared_network6_config(app)
    response = client.get("/edit-subnet6?subnet=2001:db8:50::/64&shared-network-name=TestNet6")
    assert response.status_code == 200
    assert b"2001:db8:50::100" in response.data

def test_edit_subnet6_get_not_found_redirects(client):
    response = client.get("/edit-subnet6?subnet=2001:db8:zz::/64")
    assert response.status_code == 302

def test_edit_subnet6_post_updates_na_pool_in_place(app, client):
    _write_shared_network6_config(app)
    response = client.post("/edit-subnet6", data={
        "subnet": "2001:db8:50::/64",
        "shared-network-name": "TestNet6",
        "pool-start": "2001:db8:50::200",
        "pool-end": "2001:db8:50::2ff",
    })
    assert response.status_code == 302

    dhcp6 = _read_v6_config(app)
    subnet_obj = dhcp6["shared-networks"][0]["subnet6"][0]
    assert subnet_obj["pools"] == [{"pool": "2001:db8:50::200 - 2001:db8:50::2ff"}]
    assert subnet_obj["subnet"] == "2001:db8:50::/64"  # untouched
    assert subnet_obj["id"] == 1

def test_edit_subnet6_post_cannot_change_cidr(app, client):
    _write_shared_network6_config(app)
    client.post("/edit-subnet6", data={
        "subnet": "2001:db8:50::/64",
        "shared-network-name": "TestNet6",
        "pool-start": "2001:db8:50::200",
        "pool-end": "2001:db8:50::2ff",
    })
    dhcp6 = _read_v6_config(app)
    assert dhcp6["shared-networks"][0]["subnet6"][0]["subnet"] == "2001:db8:50::/64"

def test_edit_subnet6_post_adds_pd_pool(app, client):
    _write_shared_network6_config(app)
    response = client.post("/edit-subnet6", data={
        "subnet": "2001:db8:50::/64",
        "shared-network-name": "TestNet6",
        "pd-pool": "2001:db8:51::/48",
        "pd-length": "64",
    })
    assert response.status_code == 302

    dhcp6 = _read_v6_config(app)
    subnet_obj = dhcp6["shared-networks"][0]["subnet6"][0]
    # Kea's pd-pools schema requires prefix and prefix-len as separate fields
    # -- storing the whole "prefix/len" string as "prefix" alone is rejected
    # by Kea's own syntax check with "missing parameter 'prefix-len'". See
    # AUDIT_FINDINGS.md, 2026-08-02.
    assert subnet_obj["pd-pools"] == [{
        "prefix": "2001:db8:51::",
        "prefix-len": 48,
        "delegated-len": 64,
    }]

def test_edit_subnet6_get_prefills_pd_pool_with_prefix_len(app, client):
    """The edit form's PD Pool field must show the full CIDR (prefix +
    prefix-len combined), not just the bare prefix -- otherwise re-submitting
    the pre-filled form without changes would silently drop the prefix
    length the user never touched."""
    _write_shared_network6_config(app)
    client.post("/edit-subnet6", data={
        "subnet": "2001:db8:50::/64",
        "shared-network-name": "TestNet6",
        "pd-pool": "2001:db8:51::/48",
        "pd-length": "64",
    })
    response = client.get("/edit-subnet6?subnet=2001:db8:50::/64&shared-network-name=TestNet6")
    assert response.status_code == 200
    assert b"2001:db8:51::/48" in response.data

def test_edit_subnet6_post_invalid_pd_length_returns_form_error(app, client):
    _write_shared_network6_config(app)
    response = client.post("/edit-subnet6", data={
        "subnet": "2001:db8:50::/64",
        "shared-network-name": "TestNet6",
        "pd-pool": "2001:db8:51::/48",
        "pd-length": "999999",
    })
    assert response.status_code == 400
    assert b"must be between 1 and 128" in response.data

def test_edit_reservation6_get_prefills_existing_values(app, client):
    _seed_standalone_subnet6(app)
    client.post("/new-reservation6", data={
        "subnet": "2001:db8:aa::/64",
        "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
        "hostname": "laptop-01",
        "ip-address": "2001:db8:aa::50",
    })
    response = client.get("/edit-reservation6?duid=00:03:00:01:aa:bb:cc:dd:ee:ff&subnet=2001:db8:aa::/64")
    assert response.status_code == 200
    assert b"2001:db8:aa::50" in response.data
    assert b"laptop-01" in response.data

def test_edit_reservation6_get_not_found_redirects(client):
    response = client.get("/edit-reservation6?duid=00:00:00:00:00:00&subnet=2001:db8:aa::/64")
    assert response.status_code == 302

def test_edit_reservation6_post_updates_in_place(app, client):
    _seed_standalone_subnet6(app)
    client.post("/new-reservation6", data={
        "subnet": "2001:db8:aa::/64",
        "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
        "hostname": "laptop-01",
        "ip-address": "2001:db8:aa::50",
    })
    response = client.post("/edit-reservation6", data={
        "original-duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
        "subnet": "2001:db8:aa::/64",
        "duid": "00:03:00:01:aa:bb:cc:dd:ee:00",  # typo fix
        "hostname": "renamed-laptop",
        "ip-address": "2001:db8:aa::51",
    })
    assert response.status_code == 302

    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    reservations = config["Dhcp6"]["subnet6"][0]["reservations"]
    assert len(reservations) == 1
    assert reservations[0]["duid"] == "00:03:00:01:aa:bb:cc:dd:ee:00"
    assert reservations[0]["hostname"] == "renamed-laptop"
    assert reservations[0]["ip-addresses"] == ["2001:db8:aa::51"]

def test_edit_reservation6_post_switching_to_prefix_only_clears_addresses(app, client):
    """Editing a reservation from an address to a prefix (or vice versa)
    must not leave a stale key behind from the previous type."""
    _seed_standalone_subnet6(app)
    client.post("/new-reservation6", data={
        "subnet": "2001:db8:aa::/64",
        "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
        "hostname": "router-01",
        "ip-address": "2001:db8:aa::50",
    })
    response = client.post("/edit-reservation6", data={
        "original-duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
        "subnet": "2001:db8:aa::/64",
        "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
        "hostname": "router-01",
        "prefix": "2001:db8:bb::/56",
    })
    assert response.status_code == 302

    with open(app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    reservation = config["Dhcp6"]["subnet6"][0]["reservations"][0]
    assert reservation["prefixes"] == ["2001:db8:bb::/56"]
    assert "ip-addresses" not in reservation

def test_edit_reservation6_post_duid_collision_with_another_reservation_rejected(app):
    _seed_standalone_subnet6(app)
    client = login(app.test_client(), app)
    client.post("/new-reservation6", data={
        "subnet": "2001:db8:aa::/64",
        "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
        "hostname": "one",
        "ip-address": "2001:db8:aa::50",
    })
    client.post("/new-reservation6", data={
        "subnet": "2001:db8:aa::/64",
        "duid": "00:03:00:01:aa:bb:cc:dd:ee:00",
        "hostname": "two",
        "ip-address": "2001:db8:aa::51",
    })
    response = client.post("/edit-reservation6", data={
        "original-duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
        "subnet": "2001:db8:aa::/64",
        "duid": "00:03:00:01:aa:bb:cc:dd:ee:00",  # collides with the other reservation
        "hostname": "one",
        "ip-address": "2001:db8:aa::50",
    })
    assert response.status_code == 400
    assert b"already exists" in response.data
