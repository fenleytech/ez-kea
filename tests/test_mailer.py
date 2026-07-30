# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
tests/test_mailer.py

Unit tests for ez_kea/mailer.py's SMTP plumbing and the admin-only
Email Settings page/routes in ez_kea/auth.py. Never touches a real network —
smtplib.SMTP/SMTP_SSL are always monkeypatched.
"""
from unittest.mock import MagicMock

import pytest
from ez_kea import create_app, db
from ez_kea.models import User, SystemSetting
from ez_kea import mailer
from conftest import login


@pytest.fixture
def app(tmp_path):
    settings_file = tmp_path / "settings.json"
    settings_file.write_text("{}")
    config_file = tmp_path / "kea-dhcp4.conf"
    config_file.write_text('{"Dhcp4": {"shared-networks": []}}')

    app = create_app(config_overrides={
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path}/test.db",
    })
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SETTINGS_FILE"] = str(settings_file)
    app.config["DHCP_CONFIG_FILE"] = str(config_file)
    app.config["DHCP_LEASES_FILE"] = str(tmp_path / "leases.csv")
    yield app


@pytest.fixture
def admin_client(app):
    return login(app.test_client(), app, username="admin-test", is_admin=True)


@pytest.fixture
def nonadmin_client(app):
    return login(app.test_client(), app, username="plain-user", is_admin=False)


# ── _smtp_connect ────────────────────────────────────────────────────────────

def test_smtp_connect_uses_ssl_on_port_465(monkeypatch):
    mock_ssl = MagicMock()
    mock_ssl_cls = MagicMock(return_value=mock_ssl)
    mock_plain_cls = MagicMock()
    monkeypatch.setattr(mailer.smtplib, "SMTP_SSL", mock_ssl_cls)
    monkeypatch.setattr(mailer.smtplib, "SMTP", mock_plain_cls)

    mailer._smtp_connect({"smtp_host": "h", "smtp_port": "465",
                           "smtp_username": "u", "smtp_password": "p"})

    mock_ssl_cls.assert_called_once_with("h", 465, timeout=15)
    mock_plain_cls.assert_not_called()
    mock_ssl.login.assert_called_once_with("u", "p")


def test_smtp_connect_uses_starttls_when_enabled(monkeypatch):
    mock_plain = MagicMock()
    mock_plain_cls = MagicMock(return_value=mock_plain)
    monkeypatch.setattr(mailer.smtplib, "SMTP", mock_plain_cls)

    mailer._smtp_connect({"smtp_host": "h", "smtp_port": "587", "smtp_tls": "true"})

    mock_plain_cls.assert_called_once_with("h", 587, timeout=15)
    mock_plain.starttls.assert_called_once()


def test_smtp_connect_skips_starttls_when_disabled(monkeypatch):
    mock_plain = MagicMock()
    monkeypatch.setattr(mailer.smtplib, "SMTP", MagicMock(return_value=mock_plain))

    mailer._smtp_connect({"smtp_host": "h", "smtp_port": "587", "smtp_tls": "false"})

    mock_plain.starttls.assert_not_called()


def test_smtp_connect_skips_login_without_credentials(monkeypatch):
    mock_plain = MagicMock()
    monkeypatch.setattr(mailer.smtplib, "SMTP", MagicMock(return_value=mock_plain))

    mailer._smtp_connect({"smtp_host": "h", "smtp_port": "587"})

    mock_plain.login.assert_not_called()


# ── test_smtp() ──────────────────────────────────────────────────────────────

def test_test_smtp_reports_missing_host():
    ok, msg = mailer.test_smtp({})
    assert ok is False
    assert "not configured" in msg.lower()


def test_test_smtp_reports_success(monkeypatch):
    mock_plain = MagicMock()
    monkeypatch.setattr(mailer.smtplib, "SMTP", MagicMock(return_value=mock_plain))
    ok, msg = mailer.test_smtp({"smtp_host": "h", "smtp_port": "587"})
    assert ok is True
    assert "h:587" in msg
    mock_plain.quit.assert_called_once()


def test_test_smtp_reports_connection_failure(monkeypatch):
    monkeypatch.setattr(mailer.smtplib, "SMTP", MagicMock(side_effect=OSError("refused")))
    ok, msg = mailer.test_smtp({"smtp_host": "h", "smtp_port": "587"})
    assert ok is False
    assert "refused" in msg


# ── send_password_reset_email() is never license-gated ──────────────────────

def test_send_password_reset_email_not_gated_by_license(app, monkeypatch):
    """Account recovery must keep working even with no valid license — this
    function must not import/consult ez_kea.license at all."""
    mock_server = MagicMock()
    monkeypatch.setattr(mailer.smtplib, "SMTP", MagicMock(return_value=mock_server))

    class FakeUser:
        username = "someone"
        email = "someone@example.com"

    settings = {"smtp_host": "h", "smtp_port": "587", "smtp_from": "from@example.com"}
    with app.app_context():
        ok, msg = mailer.send_password_reset_email(FakeUser(), "http://x/reset", settings)
    assert ok is True
    mock_server.sendmail.assert_called_once()


# ── admin-only Email Settings page ──────────────────────────────────────────

def test_email_settings_requires_admin(nonadmin_client):
    resp = nonadmin_client.get("/email-settings")
    assert resp.status_code == 403


def test_email_settings_page_loads_for_admin(admin_client):
    resp = admin_client.get("/email-settings")
    assert resp.status_code == 200
    assert b"SMTP" in resp.data


def test_email_settings_save_persists_settings(app, admin_client):
    resp = admin_client.post("/email-settings", data={
        "smtp_host": "smtp.example.com",
        "smtp_port": "2525",
        "smtp_username": "u@example.com",
        "smtp_password": "hunter2",
        "smtp_from": "noreply@example.com",
        "smtp_tls": "on",
        "company_name": "Acme",
        "app_url": "https://acme.example.com",
    }, follow_redirects=False)
    assert resp.status_code == 302

    with app.app_context():
        assert SystemSetting.query.get("smtp_host").value == "smtp.example.com"
        assert SystemSetting.query.get("smtp_port").value == "2525"
        assert SystemSetting.query.get("smtp_password").value == "hunter2"
        assert SystemSetting.query.get("smtp_tls").value == "true"


def test_email_settings_save_keeps_password_when_blank(app, admin_client):
    with app.app_context():
        db.session.add(SystemSetting(key="smtp_password", value="original-secret"))
        db.session.commit()

    admin_client.post("/email-settings", data={
        "smtp_host": "smtp.example.com",
        "smtp_port": "587",
        "smtp_password": "",  # blank = unchanged
    }, follow_redirects=False)

    with app.app_context():
        assert SystemSetting.query.get("smtp_password").value == "original-secret"


def test_email_settings_test_route_requires_admin(nonadmin_client):
    resp = nonadmin_client.post("/email-settings/test", json={"smtp_host": "h"})
    assert resp.status_code == 403


def test_email_settings_test_route_uses_posted_unsaved_values(app, admin_client, monkeypatch):
    mock_plain = MagicMock()
    monkeypatch.setattr(mailer.smtplib, "SMTP", MagicMock(return_value=mock_plain))

    resp = admin_client.post("/email-settings/test", json={
        "smtp_host": "posted-host.example.com",
        "smtp_port": "587",
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert "posted-host.example.com" in data["message"]
    # Nothing should have been persisted just from testing.
    with app.app_context():
        row = SystemSetting.query.get("smtp_host")
        assert row is None
