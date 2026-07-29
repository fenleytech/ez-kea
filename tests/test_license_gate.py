"""
tests/test_license_gate.py

Verifies license.py's grace-period enforcement actually blocks writes once
the free tier is exceeded and the grace period has elapsed — not just that
the banner text is computed correctly (that's covered by unit-testing
check_lease_limit() logic indirectly through this), but that a real gated
route refuses to mutate the config, while GETs keep working.
"""
import csv
import json
import time
from datetime import datetime, timedelta

import pytest
from ez_kea import create_app
from conftest import login


def _write_leases(path, count, expired=False):
    now = int(time.time())
    expire = now - 3600 if expired else now + 3600
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["address", "hwaddr", "expire"])
        for i in range(count):
            writer.writerow([f"10.0.{i // 256}.{i % 256}", f"00:00:00:00:{i:02x}:00", expire])


@pytest.fixture
def app(tmp_path):
    settings_file = tmp_path / "settings.json"
    settings_file.write_text("{}")
    config_file = tmp_path / "kea-dhcp4.conf"
    config_file.write_text(json.dumps({"Dhcp4": {"shared-networks": []}}))
    leases_file = tmp_path / "leases.csv"

    app = create_app(config_overrides={
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path}/test.db",
    })
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SETTINGS_FILE"] = str(settings_file)
    app.config["DHCP_CONFIG_FILE"] = str(config_file)
    app.config["DHCP_LEASES_FILE"] = str(leases_file)
    yield app


@pytest.fixture
def client(app):
    return login(app.test_client(), app)


def _force_grace_period_elapsed(app):
    """Simulate the 7-day grace period already having elapsed."""
    from ez_kea.license import set_grace_period_start
    with app.app_context():
        set_grace_period_start(datetime.utcnow() - timedelta(days=8))


def test_under_free_tier_limit_writes_succeed(app, client):
    _write_leases(app.config["DHCP_LEASES_FILE"], 5)
    response = client.post("/new-shared-network", data={"shared-network-name": "ok-net"})
    assert response.status_code == 302
    with open(app.config["DHCP_CONFIG_FILE"]) as f:
        config = json.load(f)
    assert any(n["name"] == "ok-net" for n in config["Dhcp4"]["shared-networks"])


def test_over_limit_within_grace_period_writes_still_succeed(app, client):
    """Crossing the limit starts the grace period but doesn't block yet."""
    _write_leases(app.config["DHCP_LEASES_FILE"], 150)
    response = client.post("/new-shared-network", data={"shared-network-name": "grace-net"})
    assert response.status_code == 302
    with open(app.config["DHCP_CONFIG_FILE"]) as f:
        config = json.load(f)
    assert any(n["name"] == "grace-net" for n in config["Dhcp4"]["shared-networks"])


def test_over_limit_past_grace_period_blocks_write(app, client):
    _write_leases(app.config["DHCP_LEASES_FILE"], 150)
    _force_grace_period_elapsed(app)

    response = client.post("/new-shared-network", data={"shared-network-name": "blocked-net"},
                            follow_redirects=False)
    assert response.status_code == 302

    with open(app.config["DHCP_CONFIG_FILE"]) as f:
        config = json.load(f)
    assert not any(n["name"] == "blocked-net" for n in config["Dhcp4"]["shared-networks"])


def test_over_limit_past_grace_period_get_still_works(app, client):
    """Viewing existing configuration must not be blocked — only writes."""
    _write_leases(app.config["DHCP_LEASES_FILE"], 150)
    _force_grace_period_elapsed(app)

    response = client.get("/pools")
    assert response.status_code == 200


def test_valid_license_bypasses_block(app, client, monkeypatch):
    _write_leases(app.config["DHCP_LEASES_FILE"], 150)
    _force_grace_period_elapsed(app)
    monkeypatch.setattr("ez_kea.license.get_license", lambda: {"valid": True, "max_leases": 0})

    response = client.post("/new-shared-network", data={"shared-network-name": "licensed-net"})
    assert response.status_code == 302
    with open(app.config["DHCP_CONFIG_FILE"]) as f:
        config = json.load(f)
    assert any(n["name"] == "licensed-net" for n in config["Dhcp4"]["shared-networks"])
