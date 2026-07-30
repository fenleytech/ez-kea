# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
tests/conftest.py

Shared test helpers for logging a Flask test client in as a real,
DB-backed user. Routes are gated with @login_required (see ez_kea/auth.py),
so route-level tests need a session that flask_login recognizes as
authenticated. We create a real User row and stash its id directly in the
test client's session the same way flask_login's login_user() does,
bypassing the password/2FA flow itself, which these route-level tests
aren't concerned with.
"""
from werkzeug.security import generate_password_hash

TEST_PASSWORD_HASH = generate_password_hash("test-password-not-used-1234567")


def create_test_user(app, username="testadmin", is_admin=True):
    """Create (or fetch) a real DB-backed user within app's own database binding.
    Returns the user's id."""
    from ez_kea import db
    from ez_kea.models import User

    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user is None:
            user = User(
                username=username,
                password_hash=TEST_PASSWORD_HASH,
                is_admin=is_admin,
            )
            db.session.add(user)
            db.session.commit()
        return user.id


def login(client, app, username="testadmin", is_admin=True):
    """Log a test client in as a real user, bypassing the login form itself."""
    uid = create_test_user(app, username=username, is_admin=is_admin)
    with client.session_transaction() as sess:
        sess["_user_id"] = str(uid)
        sess["_fresh"] = True
    return client
