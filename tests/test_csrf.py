"""
tests/test_csrf.py

Verifies AUDIT_FINDINGS.md 1.4 is actually closed: with CSRF protection
enabled (the real, non-test-suite default), a state-changing POST without a
valid token must be rejected, and a same-session POST carrying the token
generated for it must succeed.
"""
import json
import pytest
from ez_kea import create_app


@pytest.fixture
def app(tmp_path):
    settings_file = tmp_path / "settings.json"
    settings_file.write_text("{}")

    app = create_app(config_overrides={
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path}/test.db",
    })
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-only-secret-key"
    # Deliberately leave WTF_CSRF_ENABLED at its real default (True) here —
    # this is the one test file that must exercise actual enforcement.
    app.config["SETTINGS_FILE"] = str(settings_file)
    config_file = tmp_path / "kea-dhcp4.conf"
    config_file.write_text(json.dumps({"Dhcp4": {"shared-networks": []}}))
    app.config["DHCP_CONFIG_FILE"] = str(config_file)
    app.config["DHCP_LEASES_FILE"] = str(tmp_path / "leases.csv")
    yield app


@pytest.fixture
def client(app):
    # Routes are @login_required now; CSRF's before_request hook still runs
    # ahead of that check either way, so logging in here doesn't weaken what
    # this file verifies — it just lets the "legit same-session POST" case
    # actually reach the view instead of bouncing to /login first.
    from conftest import login
    return login(app.test_client(), app)


def test_post_without_csrf_token_is_rejected(client):
    """
    Live PoC from AUDIT_FINDINGS.md 1.4: a forged, tokenless POST (as a hostile
    third-party page would send) must no longer succeed.
    """
    response = client.post("/new-shared-network", data={"shared-network-name": "evil-net"})
    assert response.status_code == 400

def test_post_with_valid_csrf_token_succeeds(client):
    """The legitimate, same-session case (browser submitting the real form) must still work."""
    import re

    # Load the page that renders the form, exactly as a real browser would
    # before submitting — this both establishes the session cookie and gives
    # us the token embedded by templates/new_shared_network.html.
    get_response = client.get("/new-shared-network")
    assert get_response.status_code == 200
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', get_response.get_data(as_text=True))
    assert match, "Expected a csrf_token hidden field in the rendered form"
    token = match.group(1)

    response = client.post(
        "/new-shared-network",
        data={"shared-network-name": "legit-net", "csrf_token": token},
    )
    assert response.status_code == 302
