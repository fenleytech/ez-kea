import os
import json
from unittest.mock import patch
from ez_kea.core.discovery import discover_environment, discover_environment6


def _app_config(tmp_path, settings_file_exists=False, **overrides):
    settings_file = os.path.join(tmp_path, "settings.json")
    if settings_file_exists:
        with open(settings_file, "w") as f:
            json.dump({}, f)
    config = {"SETTINGS_FILE": settings_file}
    config.update(overrides)
    return config


def test_discover_environment6_demo_fallback(tmp_path):
    """With no saved settings, no running kea-dhcp6 process, and no standard
    install path present, v6 discovery must fall back to its own DEMO path —
    independently of whatever v4 discovery decides."""
    config = _app_config(tmp_path, DHCP6_CONFIG_FILE="./data/kea-dhcp6.conf")
    with patch("ez_kea.core.discovery.find_kea_process", return_value={}):
        with patch("os.path.isfile", return_value=False):
            result = discover_environment6(config)
    assert result["mode"] == "DEMO"
    assert result["dhcp6_config_file"] == "./data/kea-dhcp6.conf"
    assert result["kea_dhcp6_cmd"] == "kea-dhcp6"


def test_discover_environment6_live_via_running_process(tmp_path):
    config = _app_config(tmp_path)
    with patch(
        "ez_kea.core.discovery.find_kea_process",
        return_value={"pid": "1234", "config_file": "/etc/kea/kea-dhcp6.conf"},
    ):
        result = discover_environment6(config)
    assert result["mode"] == "LIVE"
    assert result["dhcp6_config_file"] == "/etc/kea/kea-dhcp6.conf"
    assert result["kea_dhcp6_cmd"] == "kea-dhcp6"


def test_discover_environment6_respects_saved_settings(tmp_path):
    settings_file = os.path.join(tmp_path, "settings.json")
    with open(settings_file, "w") as f:
        json.dump({
            "dhcp6_config_file": "/etc/kea/kea-dhcp6.conf",
            "kea_dhcp6_cmd": "/opt/kea/sbin/kea-dhcp6",
            "kea_ctrl_cmd": "keactrl",
        }, f)
    config = {"SETTINGS_FILE": settings_file}
    result = discover_environment6(config)
    assert result["mode"] == "LIVE"
    assert result["dhcp6_config_file"] == "/etc/kea/kea-dhcp6.conf"
    assert result["kea_dhcp6_cmd"] == "/opt/kea/sbin/kea-dhcp6"


def test_discover_environment6_independent_of_v4_mode(tmp_path):
    """v4 can be LIVE (a real kea-dhcp4 process running) while v6 is still
    DEMO (no kea-dhcp6 installed) — the two must not be conflated into one
    shared mode."""
    config = _app_config(tmp_path, DHCP6_CONFIG_FILE="./data/kea-dhcp6.conf")

    def fake_find(process_name="kea-dhcp4"):
        if process_name == "kea-dhcp4":
            return {"pid": "1", "config_file": "/etc/kea/kea-dhcp4.conf"}
        return {}

    with patch("ez_kea.core.discovery.find_kea_process", side_effect=fake_find):
        with patch("os.path.isfile", return_value=False):
            v4_result = discover_environment(config)
            v6_result = discover_environment6(config)

    assert v4_result["mode"] == "LIVE"
    assert v6_result["mode"] == "DEMO"
