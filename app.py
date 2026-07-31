# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

from ez_kea import create_app
from waitress import serve
import os
import sys

# Ensure Flask instance folder exists - otherwise db.create_all() fails with 'unable to open database file' on fresh clone
# (instance/ is gitignored so clone does not create it)
os.makedirs(os.path.join(os.path.dirname(__file__), "instance"), exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(__file__), "data"), exist_ok=True)

app = create_app()

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    host = os.environ.get("HOST", "127.0.0.1")

    secret_key_is_default = app.config.get("SECRET_KEY") == "dev"
    if host not in _LOOPBACK_HOSTS and secret_key_is_default:
        print(
            "Refusing to start: SECRET_KEY is still the insecure default ('dev') and "
            f"HOST={host!r} is not loopback. Set a strong, random SECRET_KEY environment "
            "variable before binding EZ-KEA to a non-local address.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Serve using waitress for local production-like execution
    serve(app, host=host, port=port)
