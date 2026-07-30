# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import pytest
from werkzeug.datastructures import MultiDict

from ez_kea.core.ha_manager import (
    find_ha_hook, get_ha_params, set_ha_config, remove_ha_config, parse_ha_form,
    DEFAULT_HA_LIBRARY_PATH,
)

VALID_HA_PARAMS = {
    "this-server-name": "server1",
    "mode": "hot-standby",
    "heartbeat-delay": 10000,
    "max-response-delay": 60000,
    "max-ack-delay": 10000,
    "max-unacked-clients": 0,
    "peers": [
        {"name": "server1", "url": "http://192.168.1.1:8000/", "role": "primary", "auto-failover": True},
        {"name": "server2", "url": "http://192.168.1.2:8000/", "role": "standby", "auto-failover": True},
    ],
}


def _base_form(**overrides):
    data = {
        "this-server-name": "server1",
        "ha-mode": "hot-standby",
        "heartbeat-delay": "10000",
        "max-response-delay": "60000",
        "max-ack-delay": "10000",
        "max-unacked-clients": "0",
        "peer-name[]": ["server1", "server2"],
        "peer-url[]": ["http://192.168.1.1:8000/", "http://192.168.1.2:8000/"],
        "peer-role[]": ["primary", "standby"],
        "peer-autofailover[]": ["yes", "yes"],
    }
    data.update(overrides)
    return MultiDict([(k, item) for k, v in data.items() for item in (v if isinstance(v, list) else [v])])


def test_find_and_get_ha_absent():
    config = {"Dhcp4": {"hooks-libraries": []}}
    assert find_ha_hook(config) is None
    assert get_ha_params(config) is None


def test_set_ha_config_preserves_other_hooks():
    config = {
        "Dhcp4": {
            "hooks-libraries": [
                {"library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so", "parameters": {}},
            ]
        }
    }
    set_ha_config(config, DEFAULT_HA_LIBRARY_PATH, VALID_HA_PARAMS, "Dhcp4")
    hooks = config["Dhcp4"]["hooks-libraries"]
    assert len(hooks) == 2
    libs = {h["library"] for h in hooks}
    assert "/usr/lib/kea/hooks/libdhcp_lease_cmds.so" in libs
    assert DEFAULT_HA_LIBRARY_PATH in libs

    ha = get_ha_params(config, "Dhcp4")
    assert ha["this-server-name"] == "server1"
    assert len(ha["peers"]) == 2


def test_set_ha_config_replaces_existing_ha_entry():
    config = {"Dhcp4": {"hooks-libraries": [{"library": DEFAULT_HA_LIBRARY_PATH, "parameters": {"high-availability": [{"mode": "load-balancing"}]}}]}}
    set_ha_config(config, DEFAULT_HA_LIBRARY_PATH, VALID_HA_PARAMS, "Dhcp4")
    assert len(config["Dhcp4"]["hooks-libraries"]) == 1
    assert get_ha_params(config, "Dhcp4")["mode"] == "hot-standby"


def test_remove_ha_config_preserves_other_hooks():
    config = {
        "Dhcp4": {
            "hooks-libraries": [
                {"library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so", "parameters": {}},
                {"library": DEFAULT_HA_LIBRARY_PATH, "parameters": {"high-availability": [VALID_HA_PARAMS]}},
            ]
        }
    }
    remove_ha_config(config, "Dhcp4")
    hooks = config["Dhcp4"]["hooks-libraries"]
    assert len(hooks) == 1
    assert hooks[0]["library"] == "/usr/lib/kea/hooks/libdhcp_lease_cmds.so"


def test_parse_ha_form_valid():
    result, errors = parse_ha_form(_base_form())
    assert errors == []
    library_path, ha_params = result
    assert library_path == DEFAULT_HA_LIBRARY_PATH
    assert ha_params["this-server-name"] == "server1"
    assert ha_params["mode"] == "hot-standby"
    assert len(ha_params["peers"]) == 2
    assert ha_params["peers"][0]["auto-failover"] is True


def test_parse_ha_form_missing_server_name():
    result, errors = parse_ha_form(_base_form(**{"this-server-name": ""}))
    assert result is None
    assert any("This Server Name" in e for e in errors)


def test_parse_ha_form_server_name_not_a_peer():
    result, errors = parse_ha_form(_base_form(**{"this-server-name": "not-a-peer"}))
    assert result is None
    assert any("must match the name of one of the peers" in e for e in errors)


def test_parse_ha_form_duplicate_peer_names():
    result, errors = parse_ha_form(_base_form(**{
        "peer-name[]": ["server1", "server1"],
        "peer-url[]": ["http://192.168.1.1:8000/", "http://192.168.1.2:8000/"],
        "peer-role[]": ["primary", "standby"],
        "peer-autofailover[]": ["yes", "yes"],
    }))
    assert result is None
    assert any("Duplicate peer name" in e for e in errors)


def test_parse_ha_form_invalid_url():
    result, errors = parse_ha_form(_base_form(**{
        "peer-url[]": ["not-a-url", "http://192.168.1.2:8000/"],
    }))
    assert result is None
    assert any("valid http" in e for e in errors)


def test_parse_ha_form_invalid_mode():
    result, errors = parse_ha_form(_base_form(**{"ha-mode": "bogus-mode"}))
    assert result is None
    assert any("Mode must be one of" in e for e in errors)


def test_parse_ha_form_requires_two_peers():
    result, errors = parse_ha_form(_base_form(**{
        "peer-name[]": ["server1"],
        "peer-url[]": ["http://192.168.1.1:8000/"],
        "peer-role[]": ["primary"],
        "peer-autofailover[]": ["yes"],
    }))
    assert result is None
    assert any("At least two peers" in e for e in errors)


def test_parse_ha_form_skips_blank_trailing_row():
    result, errors = parse_ha_form(_base_form(**{
        "peer-name[]": ["server1", "server2", ""],
        "peer-url[]": ["http://192.168.1.1:8000/", "http://192.168.1.2:8000/", ""],
        "peer-role[]": ["primary", "standby", "primary"],
        "peer-autofailover[]": ["yes", "yes", "yes"],
    }))
    assert errors == []
    _, ha_params = result
    assert len(ha_params["peers"]) == 2


def test_parse_ha_form_custom_library_path():
    result, errors = parse_ha_form(_base_form(**{"ha-library-path": "/opt/kea/hooks/libdhcp_ha.so"}))
    assert errors == []
    library_path, _ = result
    assert library_path == "/opt/kea/hooks/libdhcp_ha.so"


def test_parse_ha_form_rejects_non_so_library_path():
    result, errors = parse_ha_form(_base_form(**{"ha-library-path": "/etc/passwd"}))
    assert result is None
    assert any(".so file" in e for e in errors)
