# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
tests/test_public_demo.py

The public demo (demo/, deployed to demo.ezkea.com) still shows the login
screen — visitors are there to look at the UI, and that includes the way it
lets people in — but ships the published demo credentials already typed into
the form so nobody bounces off a password prompt.

What these tests pin down:

  - The pre-fill is opt-in. An ordinary install must never render credentials
    into its login page, because that page is the front door of something
    managing a real network.
  - When it is on, the login form is still a real login form, and the values
    it arrives with actually authenticate.
"""
import importlib
import json
import re

import pytest
from werkzeug.security import generate_password_hash

from ez_kea import create_app, db
from ez_kea.models import User


@pytest.fixture
def app(tmp_path):
    settings_file = tmp_path / "settings.json"
    settings_file.write_text("{}")
    config_file = tmp_path / "kea-dhcp4.conf"
    config_file.write_text(json.dumps({"Dhcp4": {"shared-networks": []}}))

    app = create_app(config_overrides={
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path}/test.db",
    })
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SETTINGS_FILE"] = str(settings_file)
    app.config["DHCP_CONFIG_FILE"] = str(config_file)
    yield app


def _field_value(html, field_id):
    """Pull the value="..." off the <input> with the given id, or None."""
    tag = re.search(rf'<input[^>]*id="{field_id}"[^>]*>', html, re.S)
    assert tag, f"no <input id={field_id}> in login page"
    value = re.search(r'value="([^"]*)"', tag.group(0))
    return value.group(1) if value else None


class TestPrefillIsOptIn:

    def test_ordinary_install_has_empty_login_fields(self, app):
        html = app.test_client().get("/login").get_data(as_text=True)
        assert _field_value(html, "username") in (None, "")
        assert _field_value(html, "password") in (None, "")

    def test_ordinary_install_shows_no_demo_banner(self, app):
        html = app.test_client().get("/login").get_data(as_text=True)
        assert "Public demo" not in html

    def test_public_demo_defaults_off(self):
        """Nothing but an explicit environment setting turns this on."""
        from ez_kea.config import Config
        assert Config.PUBLIC_DEMO is False

    @pytest.mark.parametrize("value,expected", [
        ("1", True), ("true", True), ("TRUE", True), ("yes", True), ("on", True),
        ("", False), ("0", False), ("false", False), ("no", False), ("maybe", False),
    ])
    def test_env_parsing(self, monkeypatch, value, expected):
        monkeypatch.setenv("PUBLIC_DEMO", value)
        import ez_kea.config as config_module
        try:
            importlib.reload(config_module)
            assert config_module.Config.PUBLIC_DEMO is expected
        finally:
            # Leave the imported module as the rest of the suite expects it.
            monkeypatch.delenv("PUBLIC_DEMO", raising=False)
            importlib.reload(config_module)


class TestPrefillWhenEnabled:

    @pytest.fixture
    def demo_app(self, app):
        app.config["PUBLIC_DEMO"] = True
        app.config["PUBLIC_DEMO_USERNAME"] = "demo"
        app.config["PUBLIC_DEMO_PASSWORD"] = "demo"
        with app.app_context():
            db.session.add(User(
                username="demo",
                password_hash=generate_password_hash("demo"),
                is_admin=False,
                must_change_password=False,
                must_change_username=False,
            ))
            db.session.commit()
        return app

    def test_credentials_are_prefilled(self, demo_app):
        html = demo_app.test_client().get("/login").get_data(as_text=True)
        assert _field_value(html, "username") == "demo"
        assert _field_value(html, "password") == "demo"

    def test_login_screen_is_still_shown(self, demo_app):
        """The point is to pre-fill the form, not to skip past it."""
        resp = demo_app.test_client().get("/login")
        html = resp.get_data(as_text=True)
        assert resp.status_code == 200
        assert 'action="/login"' in html
        assert 'name="password"' in html
        assert "Sign In" in html

    def test_visitor_is_told_the_form_is_prefilled(self, demo_app):
        html = demo_app.test_client().get("/login").get_data(as_text=True)
        assert "Public demo" in html

    def test_prefilled_values_actually_log_in(self, demo_app):
        """Guards against the pre-fill drifting out of sync with the seeded
        account — a silently broken demo, where every visitor's first click is
        an "Invalid credentials" error."""
        client = demo_app.test_client()
        html = client.get("/login").get_data(as_text=True)
        resp = client.post("/login", data={
            "username": _field_value(html, "username"),
            "password": _field_value(html, "password"),
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" not in resp.headers["Location"]

    def test_prefill_is_html_escaped(self, demo_app):
        """A password with a quote in it must not break out of the attribute."""
        demo_app.config["PUBLIC_DEMO_PASSWORD"] = 'a"><script>x</script>'
        html = demo_app.test_client().get("/login").get_data(as_text=True)
        assert "<script>x</script>" not in html
