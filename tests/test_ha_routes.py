import json
import pytest
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
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SETTINGS_FILE"] = str(settings_file)

    config_file = tmp_path / "kea-dhcp4.conf"
    config_file.write_text(json.dumps({"Dhcp4": {"subnet4": []}}))
    app.config["DHCP_CONFIG_FILE"] = str(config_file)

    config_file6 = tmp_path / "kea-dhcp6.conf"
    config_file6.write_text(json.dumps({"Dhcp6": {"subnet6": []}}))
    app.config["DHCP6_CONFIG_FILE"] = str(config_file6)

    yield app


@pytest.fixture
def client(app):
    return login(app.test_client(), app)


def _ha_form(**overrides):
    data = {
        "ha-enabled": "on",
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
    return data


def test_high_availability_page_get(client):
    response = client.get("/high-availability")
    assert response.status_code == 200
    assert b"High Availability" in response.data


def test_save_ha_config_enables_v4(client, app):
    response = client.post("/save-ha-config", data=_ha_form())
    assert response.status_code == 302

    config = json.loads(open(app.config["DHCP_CONFIG_FILE"]).read())
    hooks = config["Dhcp4"]["hooks-libraries"]
    assert len(hooks) == 1
    ha_params = hooks[0]["parameters"]["high-availability"][0]
    assert ha_params["this-server-name"] == "server1"
    assert ha_params["mode"] == "hot-standby"
    assert len(ha_params["peers"]) == 2


def test_save_ha_config_rejects_invalid_and_flashes(client, app):
    response = client.post("/save-ha-config", data=_ha_form(**{"this-server-name": ""}))
    assert response.status_code == 302
    config = json.loads(open(app.config["DHCP_CONFIG_FILE"]).read())
    assert "hooks-libraries" not in config.get("Dhcp4", {})


def test_save_ha_config_disable_removes_hook(client, app):
    client.post("/save-ha-config", data=_ha_form())
    config = json.loads(open(app.config["DHCP_CONFIG_FILE"]).read())
    assert len(config["Dhcp4"]["hooks-libraries"]) == 1

    response = client.post("/save-ha-config", data={"ha-enabled": "off"})
    assert response.status_code == 302
    config = json.loads(open(app.config["DHCP_CONFIG_FILE"]).read())
    assert config["Dhcp4"]["hooks-libraries"] == []


def test_save_ha_config6_enables_v6(client, app):
    response = client.post("/save-ha-config6", data=_ha_form())
    assert response.status_code == 302
    config = json.loads(open(app.config["DHCP6_CONFIG_FILE"]).read())
    hooks = config["Dhcp6"]["hooks-libraries"]
    assert len(hooks) == 1
    assert hooks[0]["parameters"]["high-availability"][0]["mode"] == "hot-standby"


def test_save_ha_config_preserves_other_hooks(client, app):
    config = json.loads(open(app.config["DHCP_CONFIG_FILE"]).read())
    config["Dhcp4"]["hooks-libraries"] = [
        {"library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so", "parameters": {}}
    ]
    with open(app.config["DHCP_CONFIG_FILE"], "w") as f:
        json.dump(config, f)

    client.post("/save-ha-config", data=_ha_form())

    config = json.loads(open(app.config["DHCP_CONFIG_FILE"]).read())
    libs = {h["library"] for h in config["Dhcp4"]["hooks-libraries"]}
    assert "/usr/lib/kea/hooks/libdhcp_lease_cmds.so" in libs
    assert len(config["Dhcp4"]["hooks-libraries"]) == 2


def test_api_ha_status_no_socket_returns_502(client, app):
    response = client.get("/api/ha-status")
    assert response.status_code == 502
    assert "error" in response.get_json()


def test_api_ha_status6_no_socket_returns_502(client, app):
    response = client.get("/api/ha-status6")
    assert response.status_code == 502
    assert "error" in response.get_json()
