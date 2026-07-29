import os
import json
import pytest
from unittest.mock import patch, mock_open
from ez_kea.core.config_manager import (
    load_json, save_json, extract_log_file_from_config, extract_log_file_from_config6,
    bootstrap_config, bootstrap_config6, copy_file, _DEFAULT_KEA_CONFIG, _DEFAULT_KEA6_CONFIG
)

@pytest.fixture
def temp_config_file(tmp_path):
    return os.path.join(tmp_path, "kea-dhcp4.conf")

@pytest.fixture
def temp_backup_dir(tmp_path):
    return os.path.join(tmp_path, "backups")

def test_load_json_default_when_missing(temp_config_file):
    assert load_json(temp_config_file) == _DEFAULT_KEA_CONFIG

def test_save_and_load_json(temp_config_file):
    data = {"test": "value"}
    save_json(data, temp_config_file)
    assert load_json(temp_config_file) == data

def test_extract_log_file_from_config(temp_config_file):
    # Save a config with a specific log path
    custom_config = dict(_DEFAULT_KEA_CONFIG)
    custom_config["Dhcp4"]["loggers"] = [
        {
            "name": "kea-dhcp4",
            "output_options": [{"output": "/custom/path.log"}]
        }
    ]
    save_json(custom_config, temp_config_file)
    assert extract_log_file_from_config(temp_config_file, "/default/path.log") == "/custom/path.log"

def test_extract_log_file_fallback(temp_config_file):
    # Empty config should use fallback
    save_json({}, temp_config_file)
    assert extract_log_file_from_config(temp_config_file, "/default/path.log") == "/default/path.log"

def test_bootstrap_config(temp_config_file, temp_backup_dir):
    # Should create default config
    bootstrap_config(temp_config_file, temp_backup_dir)
    assert os.path.exists(temp_config_file)
    assert os.path.exists(temp_backup_dir)
    assert load_json(temp_config_file) == _DEFAULT_KEA_CONFIG

def test_copy_file_backup_and_restore(temp_config_file, temp_backup_dir):
    data = {"foo": "bar"}
    save_json(data, temp_config_file)
    
    # Backup
    backup_path = copy_file(temp_config_file, temp_backup_dir, restore=False)
    assert backup_path is not None
    assert os.path.exists(backup_path)
    
    # Overwrite original
    save_json({"foo": "baz"}, temp_config_file)
    
    # Restore
    assert copy_file(temp_config_file, temp_backup_dir, restore=True) is True
    assert load_json(temp_config_file) == {"foo": "bar"}


# ── AUDIT_FINDINGS.md 1.7 — backup/restore path confusion ───────────────────

def test_restore_does_not_cross_config_files(tmp_path, temp_backup_dir):
    """
    Two different config files sharing the same basename-shaped backup dir
    must not be able to leak each other's backups. Previously, restore picked
    the newest ".bak." file in backup_dir regardless of which config_file it
    belonged to — this is exactly the confusion described in 1.7.
    """
    config_a = os.path.join(tmp_path, "kea-dhcp4.conf")
    config_b = os.path.join(tmp_path, "other_dir", "kea-dhcp4.conf")
    os.makedirs(os.path.dirname(config_b), exist_ok=True)

    save_json({"who": "a"}, config_a)
    save_json({"who": "b"}, config_b)

    # Back up A first, then B (B is newer / has a larger or equal timestamp).
    backup_a = copy_file(config_a, temp_backup_dir, restore=False)
    backup_b = copy_file(config_b, temp_backup_dir, restore=False)
    assert backup_a != backup_b

    # Corrupt/overwrite config A with garbage, then restore it.
    save_json({"who": "corrupted"}, config_a)
    assert copy_file(config_a, temp_backup_dir, restore=True) is True

    # Config A must come back as A's own content — never B's, even though
    # B's backup might be newer and lives in the same backup_dir.
    assert load_json(config_a) == {"who": "a"}
    # And config B must be untouched.
    assert load_json(config_b) == {"who": "b"}

def test_restore_fails_gracefully_with_no_matching_backup(temp_config_file, temp_backup_dir):
    """Restoring a config_file with no backups of its own must fail cleanly, not restore an unrelated file's backup."""
    save_json({"foo": "bar"}, temp_config_file)
    assert copy_file(temp_config_file, temp_backup_dir, restore=True) is False


# ── DHCPv6 skeleton/default-fallback support ─────────────────────────────────

@pytest.fixture
def temp_config6_file(tmp_path):
    return os.path.join(tmp_path, "kea-dhcp6.conf")

def test_load_json_default_when_missing_v4_unchanged(temp_config_file):
    """load_json() with no explicit default must keep returning the v4
    skeleton, so every existing v4 call site is unaffected by adding the
    `default` param."""
    assert load_json(temp_config_file) == _DEFAULT_KEA_CONFIG

def test_load_json_v6_default_when_missing(temp_config6_file):
    assert load_json(temp_config6_file, default=_DEFAULT_KEA6_CONFIG) == _DEFAULT_KEA6_CONFIG

def test_load_json_v6_default_on_corrupt_file(temp_config6_file):
    with open(temp_config6_file, "w") as f:
        f.write("{not valid json")
    assert load_json(temp_config6_file, default=_DEFAULT_KEA6_CONFIG) == _DEFAULT_KEA6_CONFIG

def test_bootstrap_config6(temp_config6_file, temp_backup_dir):
    bootstrap_config6(temp_config6_file, temp_backup_dir)
    assert os.path.exists(temp_config6_file)
    assert os.path.exists(temp_backup_dir)
    assert load_json(temp_config6_file, default=_DEFAULT_KEA6_CONFIG) == _DEFAULT_KEA6_CONFIG

def test_bootstrap_config_still_writes_v4_skeleton(temp_config_file, temp_backup_dir):
    """bootstrap_config() with no explicit default_config must keep writing
    the v4 skeleton, so the existing startup call site is unaffected."""
    bootstrap_config(temp_config_file, temp_backup_dir)
    assert load_json(temp_config_file) == _DEFAULT_KEA_CONFIG

def test_extract_log_file_from_config6(temp_config6_file):
    custom_config = dict(_DEFAULT_KEA6_CONFIG)
    custom_config["Dhcp6"] = dict(custom_config["Dhcp6"])
    custom_config["Dhcp6"]["loggers"] = [
        {
            "name": "kea-dhcp6",
            "output_options": [{"output": "/custom/path6.log"}]
        }
    ]
    save_json(custom_config, temp_config6_file)
    assert extract_log_file_from_config6(temp_config6_file, "/default/path6.log") == "/custom/path6.log"

def test_extract_log_file_from_config6_fallback(temp_config6_file):
    save_json({}, temp_config6_file)
    assert extract_log_file_from_config6(temp_config6_file, "/default/path6.log") == "/default/path6.log"
