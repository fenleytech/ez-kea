# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
HA config EZ-KEA writes must match what ISC's docs require, and what a
two-server Kea 3.2.1 lab showed actually works (2026-11-10):

- lease_cmds loaded before the HA hook, or both servers hang in
  SYNCING/WAITING ("'lease4-get-page' command not supported") and serve no one.
- IP literals in peer URLs: a hostname passes `kea-dhcp4 -t`, then the HA hook
  fails to load on reload.
- load-balancing pools split HA_<primary>/HA_<secondary>: unsplit, a dropped HA
  link let both servers lease the same address to different clients.
"""
import json

import pytest
from werkzeug.datastructures import MultiDict

from ez_kea import create_app
from ez_kea.core.ha_manager import (
    DEFAULT_HA_LIBRARY_PATH, DEFAULT_HA_MULTI_THREADING, get_ha_params, merged_pool_view,
    parse_ha_form, peer_config, set_ha_config, sync_lb_pool_split, validate_ha_against_config,
)
from conftest import login

HOOKS_DIR = DEFAULT_HA_LIBRARY_PATH.rsplit("/", 1)[0]


def _params(mode="hot-standby", partner_role="standby", **extra):
    params = {
        "this-server-name": "kea1",
        "mode": mode,
        "heartbeat-delay": 10000,
        "max-response-delay": 60000,
        "max-ack-delay": 10000,
        "max-unacked-clients": 10,
        "peers": [
            {"name": "kea1", "url": "http://10.0.0.1:8001/", "role": "primary", "auto-failover": True},
            {"name": "kea2", "url": "http://10.0.0.2:8001/", "role": partner_role, "auto-failover": True},
        ],
    }
    params.update(extra)
    return params


def _form(**overrides):
    data = {
        "this-server-name": "kea1",
        "ha-mode": "hot-standby",
        "heartbeat-delay": "10000",
        "max-response-delay": "60000",
        "max-ack-delay": "10000",
        "max-unacked-clients": "10",
        "peer-name[]": ["kea1", "kea2"],
        "peer-url[]": ["http://10.0.0.1:8001/", "http://10.0.0.2:8001/"],
        "peer-role[]": ["primary", "standby"],
        "peer-autofailover[]": ["yes", "yes"],
    }
    data.update(overrides)
    return MultiDict([(k, item) for k, v in data.items() for item in (v if isinstance(v, list) else [v])])


def _libs(config, key="Dhcp4"):
    return [h["library"].rsplit("/", 1)[-1] for h in config[key]["hooks-libraries"]]


# --- hooks -------------------------------------------------------------------

def test_lease_cmds_added_from_ha_library_directory():
    config = {"Dhcp4": {}}
    set_ha_config(config, "/opt/kea/hooks/libdhcp_ha.so", _params())
    assert config["Dhcp4"]["hooks-libraries"][0] == {"library": "/opt/kea/hooks/libdhcp_lease_cmds.so"}
    assert _libs(config) == ["libdhcp_lease_cmds.so", "libdhcp_ha.so"]


def test_existing_lease_cmds_is_reused_not_duplicated():
    config = {"Dhcp4": {"hooks-libraries": [{"library": "/elsewhere/libdhcp_lease_cmds.so", "parameters": {}}]}}
    set_ha_config(config, DEFAULT_HA_LIBRARY_PATH, _params())
    set_ha_config(config, DEFAULT_HA_LIBRARY_PATH, _params())
    assert _libs(config) == ["libdhcp_lease_cmds.so", "libdhcp_ha.so"]
    assert config["Dhcp4"]["hooks-libraries"][0]["library"] == "/elsewhere/libdhcp_lease_cmds.so"


def test_hook_order_flex_id_before_ha_legal_log_after():
    config = {"Dhcp4": {"hooks-libraries": [
        {"library": f"{HOOKS_DIR}/libdhcp_flex_id.so"},
        {"library": f"{HOOKS_DIR}/libdhcp_legal_log.so"},
    ]}}
    set_ha_config(config, DEFAULT_HA_LIBRARY_PATH, _params())
    assert _libs(config) == ["libdhcp_flex_id.so", "libdhcp_lease_cmds.so", "libdhcp_ha.so", "libdhcp_legal_log.so"]


def test_ha_inserted_before_legal_log_in_normal_order():
    config = {"Dhcp4": {"hooks-libraries": [{"library": f"{HOOKS_DIR}/libdhcp_legal_log.so"}]}}
    set_ha_config(config, DEFAULT_HA_LIBRARY_PATH, _params())
    assert _libs(config) == ["libdhcp_lease_cmds.so", "libdhcp_ha.so", "libdhcp_legal_log.so"]


# --- parameters ----------------------------------------------------------------

def test_dedicated_listener_block_written_by_default():
    config = {"Dhcp4": {}}
    set_ha_config(config, DEFAULT_HA_LIBRARY_PATH, _params())
    assert get_ha_params(config)["multi-threading"] == DEFAULT_HA_MULTI_THREADING


def test_unmanaged_parameters_survive_a_form_save():
    """TLS, basic auth, a tuned MT block and extra relationships have no form fields; saving must keep them."""
    existing = _params(
        **{"trust-anchor": "/etc/kea/ca.pem", "max-rejected-lease-updates": 0,
           "multi-threading": {"enable-multi-threading": True, "http-dedicated-listener": True, "http-listener-threads": 4}}
    )
    existing["peers"][1]["basic-auth-user"] = "kea"
    second_relationship = {"this-server-name": "branch2", "mode": "hot-standby", "peers": []}
    config = {"Dhcp4": {"hooks-libraries": [
        {"library": f"{HOOKS_DIR}/libdhcp_lease_cmds.so"},
        {"library": DEFAULT_HA_LIBRARY_PATH, "parameters": {"high-availability": [existing, second_relationship]}},
    ]}}

    set_ha_config(config, DEFAULT_HA_LIBRARY_PATH, _params(**{"heartbeat-delay": 5000}))

    ha_list = config["Dhcp4"]["hooks-libraries"][1]["parameters"]["high-availability"]
    ha = ha_list[0]
    assert ha["heartbeat-delay"] == 5000
    assert ha["trust-anchor"] == "/etc/kea/ca.pem"
    assert ha["max-rejected-lease-updates"] == 0
    assert ha["multi-threading"]["http-listener-threads"] == 4
    assert ha["peers"][1]["basic-auth-user"] == "kea"
    assert ha_list[1] == second_relationship


def test_removed_peer_is_dropped():
    config = {"Dhcp4": {}}
    three = _params()
    three["peers"].append({"name": "kea3", "url": "http://10.0.0.3:8001/", "role": "backup", "auto-failover": False})
    set_ha_config(config, DEFAULT_HA_LIBRARY_PATH, three)
    set_ha_config(config, DEFAULT_HA_LIBRARY_PATH, _params())
    assert [p["name"] for p in get_ha_params(config)["peers"]] == ["kea1", "kea2"]


# --- form validation ---------------------------------------------------------------

def test_hostname_peer_url_rejected():
    result, errors = parse_ha_form(_form(**{"peer-url[]": ["http://10.0.0.1:8001/", "http://kea2.lab:8001/"]}))
    assert result is None
    assert any("IP address, not a hostname" in e for e in errors)


def test_ipv6_literal_peer_url_accepted():
    result, errors = parse_ha_form(_form(**{"peer-url[]": ["http://[2001:db8::1]:8001/", "http://[2001:db8::2]:8001/"]}))
    assert errors == []


def test_blank_max_unacked_defaults_to_isc_value():
    result, errors = parse_ha_form(_form(**{"max-unacked-clients": ""}))
    assert errors == []
    assert result[1]["max-unacked-clients"] == 10


def test_response_delay_must_exceed_heartbeat():
    result, errors = parse_ha_form(_form(**{"heartbeat-delay": "10000", "max-response-delay": "10000"}))
    assert result is None
    assert any("greater than Heartbeat Delay" in e for e in errors)


@pytest.mark.parametrize("mode,roles,ok", [
    ("hot-standby", ["primary", "standby"], True),
    ("hot-standby", ["primary", "secondary"], False),
    ("load-balancing", ["primary", "secondary"], True),
    ("load-balancing", ["primary", "standby"], False),
    ("passive-backup", ["primary", "backup"], True),
    ("passive-backup", ["primary", "standby"], False),
    ("hot-standby", ["standby", "standby"], False),
])
def test_roles_must_fit_the_mode(mode, roles, ok):
    result, errors = parse_ha_form(_form(**{"ha-mode": mode, "peer-role[]": roles}))
    assert (errors == []) is ok, errors


def test_wrong_partner_role_gives_one_clear_error():
    """hot-standby with a 'secondary' peer once produced two errors ("needs a
    standby" and "extra peers must be backup") that read as if the one peer
    had to be both."""
    result, errors = parse_ha_form(_form(**{"ha-mode": "hot-standby", "peer-role[]": ["primary", "secondary"]}))
    assert result is None
    assert len(errors) == 1
    assert "one 'primary' and one 'standby' peer" in errors[0]
    assert "kea2 = secondary" in errors[0]


def test_hot_standby_with_extra_backup_peer_is_valid():
    result, errors = parse_ha_form(_form(**{
        "peer-name[]": ["kea1", "kea2", "kea3"],
        "peer-url[]": ["http://10.0.0.1:8001/", "http://10.0.0.2:8001/", "http://10.0.0.3:8001/"],
        "peer-role[]": ["primary", "standby", "backup"],
        "peer-autofailover[]": ["yes", "yes", "no"],
    }))
    assert errors == []


def test_peer_url_port_clash_with_http_control_socket():
    config = {"Dhcp4": {"control-sockets": [
        {"socket-type": "unix", "socket-name": "/run/kea/x.sock"},
        {"socket-type": "http", "socket-address": "10.0.0.1", "socket-port": 8001},
    ]}}
    errors = validate_ha_against_config(config, _params(), "Dhcp4")
    assert errors and "port 8001" in errors[0]
    config["Dhcp4"]["control-sockets"][1]["socket-port"] = 8000
    assert validate_ha_against_config(config, _params(), "Dhcp4") == []


def test_peer_config_changes_only_this_server_name():
    config = {"Dhcp4": {"subnet4": [{"id": 1, "subnet": "10.1.0.0/24"}]}}
    set_ha_config(config, DEFAULT_HA_LIBRARY_PATH, _params())
    exported = peer_config(config, "Dhcp4", "kea2")
    assert get_ha_params(exported)["this-server-name"] == "kea2"
    get_ha_params(exported)["this-server-name"] = "kea1"
    assert exported == config
    assert peer_config(config, "Dhcp4", "nobody") is None


# --- load-balancing pool split ---------------------------------------------------------

def _lb_config(pools, key="Dhcp4", pd_pools=None):
    subnet_key = "subnet4" if key == "Dhcp4" else "subnet6"
    subnet = {"id": 1, "subnet": "10.1.0.0/24" if key == "Dhcp4" else "2001:db8:1::/64", "pools": pools}
    if pd_pools is not None:
        subnet["pd-pools"] = pd_pools
    config = {key: {subnet_key: [subnet]}}
    set_ha_config(config, DEFAULT_HA_LIBRARY_PATH, _params("load-balancing", "secondary"), key)
    return config, subnet


def test_lb_splits_pool_in_half_with_server_classes():
    config, subnet = _lb_config([{"pool": "10.1.0.100 - 10.1.0.199"}])
    assert sync_lb_pool_split(config) == []
    assert subnet["pools"] == [
        {"pool": "10.1.0.100 - 10.1.0.149", "client-classes": ["HA_kea1"]},
        {"pool": "10.1.0.150 - 10.1.0.199", "client-classes": ["HA_kea2"]},
    ]


def test_lb_split_is_idempotent_and_respects_a_hand_tuned_split():
    config, subnet = _lb_config([
        {"pool": "10.1.0.100 - 10.1.0.179", "client-classes": ["HA_kea1"]},
        {"pool": "10.1.0.180 - 10.1.0.199", "client-classes": ["HA_kea2"]},
    ])
    before = json.dumps(subnet["pools"])
    sync_lb_pool_split(config)
    sync_lb_pool_split(config)
    assert json.dumps(subnet["pools"]) == before


def test_leaving_lb_joins_the_halves_back():
    config, subnet = _lb_config([{"pool": "10.1.0.100 - 10.1.0.199", "option-data": [{"name": "routers", "data": "10.1.0.1"}]}])
    sync_lb_pool_split(config)
    set_ha_config(config, DEFAULT_HA_LIBRARY_PATH, _params())  # hot-standby
    sync_lb_pool_split(config)
    assert subnet["pools"] == [{"pool": "10.1.0.100 - 10.1.0.199", "option-data": [{"name": "routers", "data": "10.1.0.1"}]}]


def test_renamed_servers_get_their_new_classes():
    config, subnet = _lb_config([{"pool": "10.1.0.100 - 10.1.0.199"}])
    sync_lb_pool_split(config)
    renamed = _params("load-balancing", "secondary", **{"this-server-name": "a"})
    renamed["peers"][0]["name"], renamed["peers"][1]["name"] = "a", "b"
    set_ha_config(config, DEFAULT_HA_LIBRARY_PATH, renamed)
    sync_lb_pool_split(config)
    assert [p["client-classes"] for p in subnet["pools"]] == [["HA_a"], ["HA_b"]]
    assert [p["pool"] for p in subnet["pools"]] == ["10.1.0.100 - 10.1.0.149", "10.1.0.150 - 10.1.0.199"]


def test_legacy_kea_gets_singular_client_class():
    config, subnet = _lb_config([{"pool": "10.1.0.100 - 10.1.0.199"}])
    sync_lb_pool_split(config, legacy_probe=lambda: True)
    assert [p["client-class"] for p in subnet["pools"]] == ["HA_kea1", "HA_kea2"]
    assert all("client-classes" not in p for p in subnet["pools"])


def test_probe_not_called_when_nothing_needs_splitting():
    config = {"Dhcp4": {"subnet4": [{"id": 1, "subnet": "10.1.0.0/24", "pools": [{"pool": "10.1.0.100 - 10.1.0.199"}]}]}}

    def boom():
        raise AssertionError("probe called without load-balancing")
    sync_lb_pool_split(config, legacy_probe=boom)


def test_shared_network_subnets_and_cidr_pools_are_split():
    config = {"Dhcp4": {"shared-networks": [{"name": "n", "subnet4": [
        {"id": 2, "subnet": "10.2.0.0/24", "pools": [{"pool": "10.2.0.0/25"}]},
    ]}]}}
    set_ha_config(config, DEFAULT_HA_LIBRARY_PATH, _params("load-balancing", "secondary"))
    sync_lb_pool_split(config)
    pools = config["Dhcp4"]["shared-networks"][0]["subnet4"][0]["pools"]
    assert [p["pool"] for p in pools] == ["10.2.0.0 - 10.2.0.63", "10.2.0.64 - 10.2.0.127"]


def test_unsplittable_and_foreign_class_pools_warn():
    config, subnet = _lb_config([
        {"pool": "10.1.0.10 - 10.1.0.10"},
        {"pool": "10.1.0.100 - 10.1.0.199", "client-classes": ["VOIP"]},
    ])
    warnings = sync_lb_pool_split(config)
    assert any("too small" in w for w in warnings)
    assert any("own client classes" in w for w in warnings)
    assert {"pool": "10.1.0.100 - 10.1.0.199", "client-classes": ["VOIP"]} in subnet["pools"]


def test_v6_pools_and_pd_pools_split_and_merge():
    config, subnet = _lb_config(
        [{"pool": "2001:db8:1::100 - 2001:db8:1::1ff"}], key="Dhcp6",
        pd_pools=[{"prefix": "2001:db8:8000::", "prefix-len": 48, "delegated-len": 56}],
    )
    sync_lb_pool_split(config)
    assert [p["pool"] for p in subnet["pools"]] == ["2001:db8:1::100 - 2001:db8:1::17f", "2001:db8:1::180 - 2001:db8:1::1ff"]
    assert [(p["prefix"], p["prefix-len"], p["client-classes"]) for p in subnet["pd-pools"]] == [
        ("2001:db8:8000::", 49, ["HA_kea1"]), ("2001:db8:8000:8000::", 49, ["HA_kea2"]),
    ]
    assert merged_pool_view(subnet["pd-pools"], "pd-pools") == [{"prefix": "2001:db8:8000::", "prefix-len": 48, "delegated-len": 56}]

    set_ha_config(config, DEFAULT_HA_LIBRARY_PATH, _params(), "Dhcp6")
    sync_lb_pool_split(config)
    assert subnet["pools"] == [{"pool": "2001:db8:1::100 - 2001:db8:1::1ff"}]
    assert subnet["pd-pools"] == [{"prefix": "2001:db8:8000::", "prefix-len": 48, "delegated-len": 56}]


# --- through the app ----------------------------------------------------------------------

@pytest.fixture
def app(tmp_path):
    settings_file = tmp_path / "settings.json"
    settings_file.write_text("{}")
    app = create_app(config_overrides={"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path}/test.db"})
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, SETTINGS_FILE=str(settings_file),
                      BACKUP_DIR=str(tmp_path / "backups"), KEA_DHCP4_CMD="")
    config_file = tmp_path / "kea-dhcp4.conf"
    config_file.write_text(json.dumps({"Dhcp4": {"subnet4": [{
        "id": 1, "subnet": "10.1.0.0/24", "pools": [{"pool": "10.1.0.100 - 10.1.0.199"}],
        "option-data": [{"name": "routers", "data": "10.1.0.1"}], "reservations": [],
    }]}}))
    app.config["DHCP_CONFIG_FILE"] = str(config_file)
    config_file6 = tmp_path / "kea-dhcp6.conf"
    config_file6.write_text(json.dumps({"Dhcp6": {"subnet6": []}}))
    app.config["DHCP6_CONFIG_FILE"] = str(config_file6)
    yield app


@pytest.fixture
def client(app):
    return login(app.test_client(), app)


def _read(app):
    return json.loads(open(app.config["DHCP_CONFIG_FILE"]).read())


def _route_form(**overrides):
    form = {k: v for k, v in _form(**overrides).lists()}
    form = {k: (v if k.endswith("[]") else v[0]) for k, v in form.items()}
    form["ha-enabled"] = "on"
    return form


def test_saving_load_balancing_splits_existing_pools_and_edits_resplit(client, app):
    client.post("/save-ha-config", data=_route_form(**{"ha-mode": "load-balancing", "peer-role[]": ["primary", "secondary"]}))
    pools = _read(app)["Dhcp4"]["subnet4"][0]["pools"]
    assert [p["client-classes"] for p in pools] == [["HA_kea1"], ["HA_kea2"]]

    page = client.get("/edit-subnet?subnet=10.1.0.0/24").get_data(as_text=True)
    assert 'value="10.1.0.100"' in page and 'value="10.1.0.199"' in page

    client.post("/edit-subnet", data={"subnet": "10.1.0.0/24", "routers": "10.1.0.1",
                                      "range-start": "10.1.0.50", "range-end": "10.1.0.89"})
    pools = _read(app)["Dhcp4"]["subnet4"][0]["pools"]
    assert pools == [
        {"pool": "10.1.0.50 - 10.1.0.69", "client-classes": ["HA_kea1"]},
        {"pool": "10.1.0.70 - 10.1.0.89", "client-classes": ["HA_kea2"]},
    ]

    client.post("/new-subnet", data={"subnet": "10.3.0.0/24", "routers": "10.3.0.1",
                                     "range-start": "10.3.0.10", "range-end": "10.3.0.19"})
    new = [s for s in _read(app)["Dhcp4"]["subnet4"] if s["subnet"] == "10.3.0.0/24"][0]
    assert [p["client-classes"] for p in new["pools"]] == [["HA_kea1"], ["HA_kea2"]]

    client.post("/save-ha-config", data={"ha-enabled": "off"})
    subnets = {s["subnet"]: s["pools"] for s in _read(app)["Dhcp4"]["subnet4"]}
    assert subnets["10.1.0.0/24"] == [{"pool": "10.1.0.50 - 10.1.0.89"}]
    assert subnets["10.3.0.0/24"] == [{"pool": "10.3.0.10 - 10.3.0.19"}]


def test_hostname_url_is_not_saved(client, app):
    client.post("/save-ha-config", data=_route_form(**{"peer-url[]": ["http://10.0.0.1:8001/", "http://kea2:8001/"]}))
    assert "hooks-libraries" not in _read(app)["Dhcp4"]


def test_port_clash_is_not_saved(client, app):
    config = _read(app)
    config["Dhcp4"]["control-sockets"] = [{"socket-type": "http", "socket-address": "10.0.0.1", "socket-port": 8001}]
    open(app.config["DHCP_CONFIG_FILE"], "w").write(json.dumps(config))
    response = client.post("/save-ha-config", data=_route_form(), follow_redirects=True)
    assert b"also one of its HTTP control sockets" in response.data
    assert "hooks-libraries" not in _read(app)["Dhcp4"]


def test_peer_config_download(client, app):
    client.post("/save-ha-config", data=_route_form())
    response = client.get("/high-availability/peer-config/4/kea2")
    assert response.status_code == 200
    assert 'filename="kea-dhcp4.kea2.conf"' in response.headers["Content-Disposition"]
    exported = json.loads(response.data)
    assert get_ha_params(exported)["this-server-name"] == "kea2"
    assert exported["Dhcp4"]["subnet4"] == _read(app)["Dhcp4"]["subnet4"]

    assert client.get("/high-availability/peer-config/4/nobody").status_code == 404
    assert client.get("/high-availability/peer-config/5/kea2").status_code == 404
    page = client.get("/high-availability").get_data(as_text=True)
    assert "/high-availability/peer-config/4/kea2" in page
