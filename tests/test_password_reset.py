# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
tests/test_password_reset.py

Verifies the "forgot password" flow actually sends a reset email via SMTP
when configured (mocking smtplib so no real email ever goes out), falls back
to the previous logger.info() behavior when SMTP isn't configured (so a
self-hosted admin without mail set up can still recover access), and that a
valid reset token still completes a real password change end-to-end.
"""
import re
from unittest.mock import MagicMock

import pytest
from ez_kea import create_app, db
from ez_kea.models import User, SystemSetting
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
def client(app):
    return app.test_client()


def _make_user_with_email(app, username="resetme", email="resetme@example.com"):
    from werkzeug.security import generate_password_hash
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user is None:
            user = User(username=username, email=email,
                        password_hash=generate_password_hash("orig-password-12345"))
            db.session.add(user)
            db.session.commit()
        return user.id


def _configure_smtp(app):
    with app.app_context():
        for key, value in {
            "smtp_host": "smtp.example.com",
            "smtp_port": "587",
            "smtp_username": "bot@example.com",
            "smtp_password": "secret",
            "smtp_from": "bot@example.com",
            "smtp_tls": "true",
        }.items():
            db.session.add(SystemSetting(key=key, value=value))
        db.session.commit()


def test_forgot_password_sends_email_when_smtp_configured(app, client, monkeypatch):
    _make_user_with_email(app)
    _configure_smtp(app)

    mock_server = MagicMock()
    mock_smtp_cls = MagicMock(return_value=mock_server)
    monkeypatch.setattr("ez_kea.mailer.smtplib.SMTP", mock_smtp_cls)

    resp = client.post("/login/forgot-password", data={"identifier": "resetme"},
                        follow_redirects=False)
    assert resp.status_code == 302

    # The mailer must have opened a real SMTP connection and sent mail —
    # never touching smtplib.SMTP_SSL since port 587 isn't 465.
    mock_smtp_cls.assert_called_once()
    assert mock_server.sendmail.called
    sendmail_args = mock_server.sendmail.call_args[0]
    assert sendmail_args[1] == ["resetme@example.com"]
    assert "Reset Password" in sendmail_args[2] or "reset" in sendmail_args[2].lower()


def test_forgot_password_falls_back_to_logging_when_smtp_not_configured(app, client, monkeypatch, caplog):
    _make_user_with_email(app)
    # No SystemSetting rows for smtp_host -> mailer.get_settings_dict() returns {}

    mock_smtp_cls = MagicMock()
    monkeypatch.setattr("ez_kea.mailer.smtplib.SMTP", mock_smtp_cls)
    monkeypatch.setattr("ez_kea.mailer.smtplib.SMTP_SSL", mock_smtp_cls)

    import logging
    with caplog.at_level(logging.INFO):
        resp = client.post("/login/forgot-password", data={"identifier": "resetme"},
                            follow_redirects=False)
    assert resp.status_code == 302

    # Never attempted to actually connect anywhere.
    mock_smtp_cls.assert_not_called()
    # The reset link must still be discoverable by an admin via the logs.
    assert any("Password reset link for resetme" in r.message for r in caplog.records)


def test_reset_password_end_to_end_with_valid_token(app, client, monkeypatch):
    uid = _make_user_with_email(app)
    _configure_smtp(app)

    mock_server = MagicMock()
    monkeypatch.setattr("ez_kea.mailer.smtplib.SMTP", MagicMock(return_value=mock_server))

    resp = client.post("/login/forgot-password", data={"identifier": "resetme"})
    assert resp.status_code == 302

    # Pull the real reset token out of the emailed body, exactly as a user
    # clicking the emailed link would.
    body = mock_server.sendmail.call_args[0][2]
    m = re.search(r"/login/reset-password/(\d+)/([\w\-]+)", body)
    assert m, f"reset URL not found in email body: {body!r}"
    found_uid, token = int(m.group(1)), m.group(2)
    assert found_uid == uid

    resp = client.post(f"/login/reset-password/{found_uid}/{token}",
                        data={"password": "brand-new-password-123456"},
                        follow_redirects=False)
    assert resp.status_code == 302

    with app.app_context():
        user = db.session.get(User, uid)
        from werkzeug.security import check_password_hash
        assert check_password_hash(user.password_hash, "brand-new-password-123456")
        # Token must be single-use.
        assert user.reset_token_hash is None


def test_reset_password_rejects_used_or_invalid_token(app, client):
    uid = _make_user_with_email(app)
    resp = client.get(f"/login/reset-password/{uid}/not-a-real-token", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/login/forgot-password")
