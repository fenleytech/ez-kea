import os
import json
import pytest
from ez_kea.core.settings_manager import load_settings, save_settings, apply_settings_to_app, _DEFAULTS
from flask import Flask

@pytest.fixture
def temp_settings_file(tmp_path):
    return os.path.join(tmp_path, "settings.json")

def test_load_settings_defaults(temp_settings_file):
    # Ensure it returns defaults when file doesn't exist
    settings = load_settings(temp_settings_file)
    assert settings == _DEFAULTS
    
def test_save_and_load_settings(temp_settings_file):
    custom_data = dict(_DEFAULTS)
    custom_data["kea_dhcp4_cmd"] = "/opt/kea/sbin/kea-dhcp4"
    save_settings(temp_settings_file, custom_data)
    
    settings = load_settings(temp_settings_file)
    assert settings["kea_dhcp4_cmd"] == "/opt/kea/sbin/kea-dhcp4"

def test_apply_settings_to_app(temp_settings_file):
    app = Flask(__name__)
    app.config["SETTINGS_FILE"] = temp_settings_file
    # Set default values
    app.config["KEA_DHCP4_CMD"] = "kea-dhcp4"

    custom_data = dict(_DEFAULTS)
    custom_data["kea_dhcp4_cmd"] = "/custom/kea-dhcp4"
    save_settings(temp_settings_file, custom_data)

    apply_settings_to_app(app)

    # ensure it overrides default app.config
    assert app.config["KEA_DHCP4_CMD"] == "/custom/kea-dhcp4"


# ── DHCPv6 settings ───────────────────────────────────────────────────────

def test_defaults_include_v6_keys():
    assert _DEFAULTS["kea_dhcp6_cmd"] == "kea-dhcp6"
    assert _DEFAULTS["dhcp6_config_file"] == "./data/kea-dhcp6.conf"
    assert _DEFAULTS["dhcp6_leases_file"] == "./data/kea-leases6.csv"
    assert _DEFAULTS["dhcp6_log_file"] == "./data/kea-dhcp6.log"

def test_save_and_load_settings_v6(temp_settings_file):
    custom_data = dict(_DEFAULTS)
    custom_data["dhcp6_config_file"] = "/etc/kea/kea-dhcp6.conf"
    save_settings(temp_settings_file, custom_data)

    settings = load_settings(temp_settings_file)
    assert settings["dhcp6_config_file"] == "/etc/kea/kea-dhcp6.conf"

def test_apply_settings_to_app_v6(temp_settings_file):
    app = Flask(__name__)
    app.config["SETTINGS_FILE"] = temp_settings_file
    app.config["KEA_DHCP6_CMD"] = "kea-dhcp6"
    app.config["DHCP6_CONFIG_FILE"] = "./data/kea-dhcp6.conf"

    custom_data = dict(_DEFAULTS)
    custom_data["kea_dhcp6_cmd"] = "/custom/kea-dhcp6"
    custom_data["dhcp6_config_file"] = "/custom/kea-dhcp6.conf"
    save_settings(temp_settings_file, custom_data)

    apply_settings_to_app(app)

    assert app.config["KEA_DHCP6_CMD"] == "/custom/kea-dhcp6"
    assert app.config["DHCP6_CONFIG_FILE"] == "/custom/kea-dhcp6.conf"

def test_apply_settings_to_app_v6_in_container_overrides(temp_settings_file):
    app = Flask(__name__)
    app.config["SETTINGS_FILE"] = temp_settings_file

    custom_data = dict(_DEFAULTS)
    custom_data["dhcp6_config_file_in_container"] = "/in-container/kea-dhcp6.conf"
    save_settings(temp_settings_file, custom_data)

    apply_settings_to_app(app)

    assert app.config["DHCP6_CONFIG_FILE_IN_CONTAINER"] == "/in-container/kea-dhcp6.conf"
