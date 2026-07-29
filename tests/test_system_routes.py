import os
import pytest
from flask import Flask
from unittest.mock import patch, mock_open

# We need to test the endpoints in system_bp
from ez_kea.routes.system import system_bp

@pytest.fixture
def app(tmp_path):
    # Setup a minimalist Flask app for testing the blueprint. Routes are now
    # @login_required, so this also wires up (a test-only, tmp_path-backed)
    # db + login_manager rather than the real ones create_app() would use.
    from ez_kea import db, login_manager

    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret"
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{tmp_path}/test.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["DHCP_CONFIG_FILE"] = "/dummy/path/kea-dhcp4.conf"
    app.config["DHCP6_CONFIG_FILE"] = "/dummy/path/kea-dhcp6.conf"
    app.config["BACKUP_DIR"] = "/dummy/path/backups/"
    app.config["KEA_DHCP4_CMD"] = "kea-dhcp4"
    app.config["KEA_DHCP6_CMD"] = "kea-dhcp6"
    app.config["KEA_CTRL_CMD"] = "keactrl"
    app.register_blueprint(system_bp)
    db.init_app(app)
    login_manager.init_app(app)
    with app.app_context():
        from ez_kea.models import User  # noqa: F401
        db.create_all()
    yield app

@pytest.fixture
def client(app):
    from conftest import login
    return login(app.test_client(), app)

@pytest.fixture(autouse=True)
def mock_kea_binaries(monkeypatch):
    """
    The `kea-dhcp4`/`keactrl` binaries used throughout these tests are never
    actually installed in the test environment — only `subprocess.run` itself
    is mocked. Since AUDIT_FINDINGS.md 1.1's fix requires the configured
    command to resolve to a real, executable binary before we even attempt to
    run it, simulate that resolution succeeding for the allowed binary names
    so these tests continue to exercise the subprocess-mocking behavior they
    care about. Basename allowlisting (the actual security boundary) is NOT
    bypassed by this — an unlisted name like '/tmp/evil.sh' is still rejected
    regardless of what `which`/`access` report.
    """
    monkeypatch.setattr(
        "ez_kea.core.security.shutil.which",
        lambda name: f"/usr/sbin/{name}",
    )
    monkeypatch.setattr("ez_kea.core.security.os.access", lambda path, mode: True)
    monkeypatch.setattr("ez_kea.core.security.os.path.isfile", lambda path: True)

@pytest.fixture
def global_settings_app(tmp_path):
    """A fully-wired app (via create_app, matching the "main.system.*"
    endpoint names used internally by redirect/url_for) with real backing
    files, for exercising /global-settings and /save-global-settings."""
    from ez_kea import create_app

    settings_file = tmp_path / "settings.json"
    settings_file.write_text("{}")

    app = create_app(config_overrides={
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path}/test.db",
    })
    app.config["TESTING"] = True
    # These tests exercise timer/interface validation logic, not CSRF (which
    # has its own dedicated coverage in test_csrf.py) — disable it here so a
    # raw form POST isn't rejected before reaching the code under test.
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SETTINGS_FILE"] = str(settings_file)
    config_file = tmp_path / "kea-dhcp4.conf"
    config_file.write_text('{"Dhcp4": {"shared-networks": []}}')
    app.config["DHCP_CONFIG_FILE"] = str(config_file)
    app.config["BACKUP_DIR"] = str(tmp_path / "backups")
    app.config["DHCP_LEASES_FILE"] = str(tmp_path / "leases.csv")
    app.config["DHCP_LOG_FILE"] = str(tmp_path / "kea.log")

    config6_file = tmp_path / "kea-dhcp6.conf"
    config6_file.write_text('{"Dhcp6": {"shared-networks": []}}')
    app.config["DHCP6_CONFIG_FILE"] = str(config6_file)
    app.config["DHCP6_LEASES_FILE"] = str(tmp_path / "leases6.csv")
    app.config["DHCP6_LOG_FILE"] = str(tmp_path / "kea6.log")
    yield app

@pytest.fixture
def global_settings_client(global_settings_app):
    from conftest import login
    return login(global_settings_app.test_client(), global_settings_app)

@patch('ez_kea.routes.system.copy_file')
def test_backup_config(mock_copy_file, client):
    """Test the /backup-config endpoint successfully calls copy_file."""
    response = client.post("/backup-config", headers={"Referer": "/some/page"})
    
    # Check that copy_file was called with the correct app config vars
    mock_copy_file.assert_called_once_with("/dummy/path/kea-dhcp4.conf", "/dummy/path/backups/")
    # Check that we redirect back to the referrer
    assert response.status_code == 302
    assert response.location == "/some/page"

@patch('ez_kea.routes.system.copy_file')
def test_restore_config(mock_copy_file, client):
    """Test the /restore-config endpoint successfully calls copy_file with restore=True."""
    response = client.post("/restore-config", headers={"Referer": "/some/page"})
    
    # Check that copy_file was called with restore=True
    mock_copy_file.assert_called_once_with("/dummy/path/kea-dhcp4.conf", "/dummy/path/backups/", restore=True)
    # Check that we redirect back to the referrer
    assert response.status_code == 302
    assert response.location == "/some/page"

@patch('ez_kea.routes.system.copy_file')
def test_backup_config_failure(mock_copy_file, client):
    """Test /backup-config handles errors."""
    mock_copy_file.side_effect = Exception("Permission denied")
    response = client.post("/backup-config")
    
    assert response.status_code == 500
    assert b"Permission denied" in response.data

@patch('subprocess.run')
def test_syntax_check_success(mock_subprocess_run, client):
    """Test /test-config endpoint when Kea syntax check passes."""
    # Setup mock to return a successful result (return code 0)
    mock_subprocess_run.return_value.returncode = 0
    
    response = client.post("/test-config")
    
    # Check that subprocess.run was called with the right constructed command
    mock_subprocess_run.assert_called_once()
    called_args = mock_subprocess_run.call_args[0][0]
    assert "kea-dhcp4" in called_args
    assert "-t" in called_args
    assert "/dummy/path/kea-dhcp4.conf" in called_args
    
    assert response.status_code == 200
    assert response.json == {"message": "Syntax check passed!"}

@patch('subprocess.run')
def test_syntax_check_failure(mock_subprocess_run, client):
    """Test /test-config endpoint when Kea syntax check fails."""
    import subprocess
    # Setup mock to raise a CalledProcessError (simulating a non-zero exit code)
    mock_error = subprocess.CalledProcessError(
        returncode=1,
        cmd=["kea-dhcp4", "-t", "/dummy/path/kea-dhcp4.conf"],
        output="Some stdout info",
        stderr="Syntax check failed: Parse error at line 10"
    )
    mock_subprocess_run.side_effect = mock_error
    
    response = client.post("/test-config")
    
    assert response.status_code == 500
    assert "Syntax error" in response.json["error"]
    assert "Parse error at line 10" in response.json["error"]
    assert "Some stdout info" in response.json["error"]

@patch('subprocess.run')
def test_apply_config_success(mock_subprocess_run, client):
    """Test /apply-config endpoint successfully reloads."""
    # Setup mock to return a successful result for BOTH test-config and apply-config
    mock_subprocess_run.return_value.returncode = 0
    
    response = client.post("/apply-config")
    
    assert mock_subprocess_run.call_count == 2
    # Verify the reload command was the second one
    called_args = mock_subprocess_run.call_args_list[1][0][0]
    assert "keactrl" in called_args
    assert "reload" in called_args
    
    assert response.status_code == 200
    assert response.json == {"message": "KEA service reloaded successfully!"}

@patch('subprocess.run')
def test_apply_config_syntax_failure(mock_subprocess_run, client):
    """Test /apply-config endpoint fails and aborts if syntax check fails."""
    import subprocess
    mock_error = subprocess.CalledProcessError(
        returncode=1,
        cmd=["kea-dhcp4", "-t", "/dummy/path/kea-dhcp4.conf"],
        output="",
        stderr="Syntax check failed!"
    )
    mock_subprocess_run.side_effect = mock_error
    
    response = client.post("/apply-config")
    
    # Should fail in test_config step, so only 1 call is made
    mock_subprocess_run.assert_called_once()
    assert response.status_code == 500
    assert "Syntax error" in response.json["error"]

@patch('subprocess.run')
def test_apply_config_reload_failure(mock_subprocess_run, client):
    """Test /apply-config endpoint fails during the reload step."""
    import subprocess
    # First call (test_config) succeeds, second call (reload) fails
    mock_error = subprocess.CalledProcessError(
        returncode=1,
        cmd=["keactrl", "reload"],
        output="",
        stderr="Failed to connect to Kea Control Socket"
    )
    mock_subprocess_run.side_effect = [subprocess.CompletedProcess(args=[], returncode=0), mock_error]
    
    response = client.post("/apply-config")

    assert mock_subprocess_run.call_count == 2
    assert response.status_code == 500
    assert "KEA service reload failed" in response.json["error"]
    assert "Failed to connect" in response.json["error"]

@patch('subprocess.run')
def test_syntax_check_missing_binary(mock_subprocess_run, client):
    """Regression test for AUDIT_FINDINGS 2.5: /test-config only caught
    subprocess.CalledProcessError, so a missing Kea binary raised an
    uncaught FileNotFoundError -> raw Flask 500 instead of the app's own
    JSON error format."""
    mock_subprocess_run.side_effect = FileNotFoundError("[Errno 2] No such file or directory: 'kea-dhcp4'")

    response = client.post("/test-config")

    assert response.status_code == 500
    assert response.is_json
    assert "binary not found" in response.json["error"]

@patch('subprocess.run')
def test_apply_config_missing_reload_binary(mock_subprocess_run, client):
    """Regression test for AUDIT_FINDINGS 2.5: /apply-config's reload step
    only caught subprocess.CalledProcessError, so a missing keactrl binary
    raised an uncaught FileNotFoundError."""
    import subprocess
    mock_subprocess_run.side_effect = [
        subprocess.CompletedProcess(args=[], returncode=0),
        FileNotFoundError("[Errno 2] No such file or directory: 'keactrl'"),
    ]

    response = client.post("/apply-config")

    assert mock_subprocess_run.call_count == 2
    assert response.status_code == 500
    assert response.is_json
    assert "control binary not found" in response.json["error"]

def test_save_global_settings_non_numeric_timer_returns_form_error(global_settings_client):
    """Regression test for AUDIT_FINDINGS 2.5: save_global_settings() used
    a bare int() with no try/except on timer fields, so a non-numeric
    value caused an unhandled 500 instead of a graceful form error."""
    response = global_settings_client.post("/save-global-settings", data={
        "valid-lifetime": "not-a-number",
    })
    assert response.status_code == 400
    assert b"must be a whole number" in response.data

@pytest.mark.parametrize("value", ["-5", "0", "99999999999"])
def test_save_global_settings_timer_bounds_rejected(global_settings_client, value):
    """Regression test for AUDIT_FINDINGS 2.7: global timers accepted
    negative, zero, and arbitrarily large values with no bounds check."""
    response = global_settings_client.post("/save-global-settings", data={
        "valid-lifetime": value,
    })
    assert response.status_code == 400
    assert b"must be between" in response.data

def test_save_global_settings_valid_timer_persists(global_settings_app):
    from conftest import login
    client = login(global_settings_app.test_client(), global_settings_app)
    response = client.post("/save-global-settings", data={"valid-lifetime": "4000"})
    assert response.status_code == 302

    import json
    with open(global_settings_app.config["DHCP_CONFIG_FILE"]) as f:
        config = json.load(f)
    assert config["Dhcp4"]["valid-lifetime"] == 4000

def test_save_global_settings_dedupes_interfaces(global_settings_app):
    """Regression test for AUDIT_FINDINGS 2.7: interfaces-config accepted
    duplicate interface names with no de-duplication."""
    from conftest import login
    client = login(global_settings_app.test_client(), global_settings_app)
    response = client.post("/save-global-settings", data={
        "interfaces-config": "eth0, eth1, eth0, eth1, eth2",
    })
    assert response.status_code == 302

    import json
    with open(global_settings_app.config["DHCP_CONFIG_FILE"]) as f:
        config = json.load(f)
    assert config["Dhcp4"]["interfaces-config"]["interfaces"] == ["eth0", "eth1", "eth2"]


# ── DHCPv6 global settings ───────────────────────────────────────────────────

def test_global_settings_v6_get(global_settings_client):
    response = global_settings_client.get("/global-settings/6")
    assert response.status_code == 200

def test_global_settings_invalid_version_rejected(global_settings_client):
    response = global_settings_client.get("/global-settings/7")
    assert response.status_code == 400

def test_save_global_settings_v6_preferred_lifetime_persists(global_settings_app):
    import json
    from conftest import login
    client = login(global_settings_app.test_client(), global_settings_app)
    response = client.post("/save-global-settings/6", data={
        "valid-lifetime": "4000",
        "preferred-lifetime": "3000",
    })
    assert response.status_code == 302

    with open(global_settings_app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    assert config["Dhcp6"]["preferred-lifetime"] == 3000
    assert config["Dhcp6"]["valid-lifetime"] == 4000

@pytest.mark.parametrize("value", ["-5", "0", "99999999999"])
def test_save_global_settings_v6_preferred_lifetime_bounds_rejected(global_settings_client, value):
    response = global_settings_client.post("/save-global-settings/6", data={
        "preferred-lifetime": value,
    })
    assert response.status_code == 400
    assert b"must be between" in response.data

def test_save_global_settings_v6_server_id_persists(global_settings_app):
    import json
    from conftest import login
    client = login(global_settings_app.test_client(), global_settings_app)
    response = client.post("/save-global-settings/6", data={
        "server-id-type": "LLT",
        "server-id-identifier": "00:03:00:01:aa:bb:cc:dd:ee:ff",
    })
    assert response.status_code == 302

    with open(global_settings_app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    assert config["Dhcp6"]["server-id"]["type"] == "LLT"
    assert config["Dhcp6"]["server-id"]["identifier"] == "00:03:00:01:aa:bb:cc:dd:ee:ff"

def test_save_global_settings_v6_options_persist(global_settings_app):
    import json
    from conftest import login
    client = login(global_settings_app.test_client(), global_settings_app)
    response = client.post("/save-global-settings/6", data={
        "opt-dns6": "2001:4860:4860::8888",
        "opt-domain-search6": "home.local",
    })
    assert response.status_code == 302

    with open(global_settings_app.config["DHCP6_CONFIG_FILE"]) as f:
        config = json.load(f)
    opts = {o["name"]: o["data"] for o in config["Dhcp6"]["option-data"]}
    assert opts["dns-servers"] == "2001:4860:4860::8888"
    assert opts["domain-search"] == "home.local"

def test_save_global_settings_v6_repoint_requires_dhcp6_key(global_settings_app, tmp_path):
    """Regression test mirroring the v4 AUDIT_FINDINGS.md 1.3 repoint-safety
    check: repointing DHCP6_CONFIG_FILE at a file that already exists but
    isn't a valid Dhcp6 config must be refused, not silently overwritten."""
    import json
    bad_target = tmp_path / "not-a-kea6-config.conf"
    bad_target.write_text('{"Dhcp4": {}}')  # wrong root key for a v6 config

    from conftest import login
    client = login(global_settings_app.test_client(), global_settings_app)
    response = client.post("/save-global-settings/6", data={
        "dhcp6-config-file": str(bad_target),
    })
    assert response.status_code == 302
    # Should NOT have overwritten the bad target file.
    with open(bad_target) as f:
        content = json.load(f)
    assert content == {"Dhcp4": {}}

def test_save_global_settings_v4_does_not_clobber_v6_settings(global_settings_app):
    """Regression test for the settings-file merge bug: saving v4 settings
    must not wipe out previously-saved v6 settings (and vice versa), since
    both now live in the same ez-kea-settings.json file."""
    import json
    from conftest import login
    client = login(global_settings_app.test_client(), global_settings_app)

    # Save a distinctive v6 command first.
    client.post("/save-global-settings/6", data={"kea-dhcp6-cmd": "/custom/kea-dhcp6"})
    # Now save v4 settings — must not blank out the v6 command just set.
    client.post("/save-global-settings", data={"valid-lifetime": "4000"})

    with open(global_settings_app.config["SETTINGS_FILE"]) as f:
        settings = json.load(f)
    assert settings["kea_dhcp6_cmd"] == "/custom/kea-dhcp6"

def test_save_global_settings_v6_does_not_clobber_v4_settings(global_settings_app):
    import json
    from conftest import login
    client = login(global_settings_app.test_client(), global_settings_app)

    client.post("/save-global-settings", data={"valid-lifetime": "4000"})
    dhcp4_cmd_before = global_settings_app.config["KEA_DHCP4_CMD"]
    client.post("/save-global-settings/6", data={"preferred-lifetime": "3000"})

    with open(global_settings_app.config["SETTINGS_FILE"]) as f:
        settings = json.load(f)
    assert settings["kea_dhcp4_cmd"] == dhcp4_cmd_before


# ── AUDIT_FINDINGS.md 1.1 — RCE via kea_dhcp4_cmd/kea_ctrl_cmd ──────────────

@patch('subprocess.run')
def test_syntax_check_rejects_arbitrary_binary(mock_subprocess_run, app, client):
    """
    Live PoC from AUDIT_FINDINGS.md 1.1: pointing KEA_DHCP4_CMD at an arbitrary
    script must be rejected before subprocess.run is ever called.
    """
    app.config["KEA_DHCP4_CMD"] = "/tmp/evil.sh"

    response = client.post("/test-config")

    mock_subprocess_run.assert_not_called()
    assert response.status_code == 400
    assert "not an allowed executable" in response.json["error"]

@patch('subprocess.run')
def test_apply_config_rejects_arbitrary_ctrl_binary(mock_subprocess_run, app, client):
    """Same PoC, but via KEA_CTRL_CMD on the reload step."""
    app.config["KEA_CTRL_CMD"] = "/tmp/evil.sh"

    response = client.post("/apply-config")

    # test_config (kea-dhcp4) succeeds, but the reload step must refuse to run.
    assert mock_subprocess_run.call_count == 1
    assert response.status_code == 400
    assert "not an allowed executable" in response.json["error"]

@patch('subprocess.run')
def test_syntax_check_allows_docker_exec_pattern(mock_subprocess_run, app, client):
    """The documented `docker exec kea-testbed-kea-1 kea-dhcp4` pattern must still work."""
    mock_subprocess_run.return_value.returncode = 0
    app.config["KEA_DHCP4_CMD"] = "docker exec kea-testbed-kea-1 kea-dhcp4"

    response = client.post("/test-config")

    mock_subprocess_run.assert_called_once()
    called_args = mock_subprocess_run.call_args[0][0]
    assert called_args[:4] == ["docker", "exec", "kea-testbed-kea-1", "kea-dhcp4"]
    assert response.status_code == 200

@patch('subprocess.run')
def test_syntax_check_rejects_docker_exec_non_kea_target(mock_subprocess_run, app, client):
    """`docker exec <container> <anything else>` must not be allowed."""
    app.config["KEA_DHCP4_CMD"] = "docker exec kea-testbed-kea-1 /bin/sh"

    response = client.post("/test-config")

    mock_subprocess_run.assert_not_called()
    assert response.status_code == 400


# ── DHCPv6: version-aware test/apply/backup/restore ─────────────────────────
#
# Regression coverage for the confirmed bug where DHCPv6 pages' Test/Apply/
# Backup/Restore buttons silently acted on the v4 daemon: every route below
# now takes an explicit version ("4" or "6"), defaulting to "4" for the
# original unparameterized URLs so nothing that already points at them breaks.

@patch('ez_kea.routes.system.copy_file')
def test_backup_config_v6(mock_copy_file, client):
    response = client.post("/backup-config/6", headers={"Referer": "/some/page"})
    mock_copy_file.assert_called_once_with("/dummy/path/kea-dhcp6.conf", "/dummy/path/backups/")
    assert response.status_code == 302

@patch('ez_kea.routes.system.copy_file')
def test_restore_config_v6(mock_copy_file, client):
    response = client.post("/restore-config/6", headers={"Referer": "/some/page"})
    mock_copy_file.assert_called_once_with("/dummy/path/kea-dhcp6.conf", "/dummy/path/backups/", restore=True)
    assert response.status_code == 302

@patch('subprocess.run')
def test_syntax_check_v6(mock_subprocess_run, client):
    mock_subprocess_run.return_value.returncode = 0

    response = client.post("/test-config/6")

    called_args = mock_subprocess_run.call_args[0][0]
    assert "kea-dhcp6" in called_args
    assert "-t" in called_args
    assert "/dummy/path/kea-dhcp6.conf" in called_args
    assert response.status_code == 200

@patch('subprocess.run')
def test_apply_config_v6(mock_subprocess_run, client):
    mock_subprocess_run.return_value.returncode = 0

    response = client.post("/apply-config/6")

    assert mock_subprocess_run.call_count == 2
    test_call_args = mock_subprocess_run.call_args_list[0][0][0]
    assert "kea-dhcp6" in test_call_args
    assert response.status_code == 200

@pytest.mark.parametrize("route", ["/test-config", "/apply-config", "/backup-config", "/restore-config"])
def test_invalid_dhcp_version_rejected(route, client):
    """A version other than '4'/'6' must be rejected explicitly, not silently
    fall through to acting on the wrong daemon."""
    response = client.post(f"{route}/7")
    assert response.status_code == 400

def test_test_config_bare_route_still_targets_v4(client):
    """The original unparameterized /test-config route must keep acting on
    v4 — existing bookmarks/scripts/tests must not silently start hitting v6."""
    with patch('subprocess.run') as mock_subprocess_run:
        mock_subprocess_run.return_value.returncode = 0
        response = client.post("/test-config")
    called_args = mock_subprocess_run.call_args[0][0]
    assert "kea-dhcp4" in called_args
    assert "/dummy/path/kea-dhcp4.conf" in called_args
    assert response.status_code == 200


# ── save-global-settings: command validation, log path validation, repoint ──

@pytest.fixture
def full_app(tmp_path):
    """
    A more complete fixture for exercising /save-global-settings, which touches
    settings_manager (SETTINGS_FILE), the leases/log paths, and a real config
    file on disk — unlike the minimal `app` fixture used for test/apply-config.

    save_global_settings() redirects via url_for("main.system.global_settings"),
    so system_bp needs to be nested under a "main" blueprint exactly like the
    real app factory does (ez_kea/routes/__init__.py), not registered standalone.
    """
    from flask import Blueprint
    from ez_kea import db, login_manager

    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret"
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{tmp_path}/test.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    config_file = tmp_path / "kea-dhcp4.conf"
    config_file.write_text('{"Dhcp4": {"shared-networks": []}}')
    app.config["DHCP_CONFIG_FILE"] = str(config_file)
    app.config["DHCP_LEASES_FILE"] = str(tmp_path / "kea-leases4.csv")
    app.config["DHCP_LOG_FILE"] = str(tmp_path / "kea-dhcp4.log")
    app.config["BACKUP_DIR"] = str(tmp_path / "backups")
    app.config["SETTINGS_FILE"] = str(tmp_path / "ez-kea-settings.json")
    app.config["KEA_DHCP4_CMD"] = "kea-dhcp4"
    app.config["KEA_CTRL_CMD"] = "keactrl"
    main_bp = Blueprint('main', __name__)
    main_bp.register_blueprint(system_bp)
    app.register_blueprint(main_bp)
    db.init_app(app)
    login_manager.init_app(app)
    with app.app_context():
        from ez_kea.models import User  # noqa: F401
        db.create_all()
    return app

@pytest.fixture
def full_client(full_app):
    from conftest import login
    return login(full_app.test_client(), full_app)

def test_save_settings_rejects_new_malicious_dhcp4_cmd(full_client):
    """Live PoC from AUDIT_FINDINGS.md 1.1, via the save-settings form field itself."""
    response = full_client.post("/save-global-settings", data={"kea-dhcp4-cmd": "/tmp/evil.sh"})
    assert response.status_code == 302  # redirects back with a flashed error, nothing saved

def test_save_settings_unrelated_change_survives_unresolvable_existing_command(full_app, full_client, monkeypatch):
    """
    Regression test: an operator's already-configured kea-dhcp4-cmd/kea-ctrl-cmd
    must NOT be re-validated on every save if the operator isn't touching those
    fields. Otherwise, the moment the previously-valid binary stops resolving
    on this host (e.g. dev machine without Kea installed, PATH change), an
    unrelated settings change (like updating DNS servers) would be blocked
    outright — a real usability regression uncovered while manually verifying
    the 1.1 fix end-to-end.
    """
    # Simulate the currently-configured kea-dhcp4/keactrl NOT resolving on this host.
    monkeypatch.setattr("ez_kea.core.security.shutil.which", lambda name: None)

    response = full_client.post("/save-global-settings", data={"opt-dns": "1.1.1.1"})
    assert response.status_code == 302

    with full_app.test_request_context():
        from ez_kea.core.config_manager import load_json
        config = load_json(full_app.config["DHCP_CONFIG_FILE"])
    opts = {o["name"]: o["data"] for o in config["Dhcp4"].get("option-data", [])}
    assert opts.get("domain-name-servers") == "1.1.1.1"

def test_save_settings_rejects_new_malicious_log_file(full_client):
    """Live PoC from AUDIT_FINDINGS.md 1.2, via the save-settings form field itself."""
    response = full_client.post("/save-global-settings", data={"dhcp-log-file": "/etc/passwd"})
    assert response.status_code == 302  # redirects back with a flashed error, nothing saved

    with full_client.session_transaction() as sess:
        flashes = dict(sess.get("_flashes", []))
    assert any("outside the allowed log directories" in msg for msg in flashes.values())

def test_save_settings_repoint_does_not_overwrite_new_target(full_app, full_client, tmp_path):
    """
    Live PoC from AUDIT_FINDINGS.md 1.3: repointing dhcp-config-file to a fresh
    path in the same request that saves other settings must NOT also write the
    old config's content over that new path.
    """
    canary = tmp_path / "victim_file.txt"
    canary.write_text("original victim content — must not be touched")

    response = full_client.post(
        "/save-global-settings",
        data={"dhcp-config-file": str(canary), "opt-dns": "9.9.9.9"},
    )
    assert response.status_code == 302
    # The repoint is flagged invalid because the target isn't parseable Kea JSON,
    # so the canary's content must be completely untouched.
    assert canary.read_text() == "original victim content — must not be touched"

def test_save_settings_repoint_to_nonexistent_path_is_pure_pointer_switch(full_app, full_client, tmp_path):
    """A repoint to a path that doesn't exist yet (first-time setup) must not carry over old content."""
    new_path = tmp_path / "brand_new_kea_dir" / "kea-dhcp4.conf"

    response = full_client.post(
        "/save-global-settings",
        data={"dhcp-config-file": str(new_path), "opt-dns": "9.9.9.9"},
    )
    assert response.status_code == 302
    assert new_path.exists()  # bootstrap_config wrote a fresh skeleton

    with full_app.test_request_context():
        from ez_kea.core.config_manager import load_json
        config = load_json(str(new_path))
    # The unrelated opt-dns edit from this same request must NOT have been
    # applied to the new file — repoint is a distinct action.
    opts = {o["name"]: o["data"] for o in config["Dhcp4"].get("option-data", [])}
    assert "domain-name-servers" not in opts
