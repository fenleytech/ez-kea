from ez_kea import create_app
from waitress import serve
import os
import sys

app = create_app()

# AUDIT_FINDINGS.md finding 6 / 1.5: EZ-Kea used to hardcode host="0.0.0.0",
# meaning zero-config startup was internet/LAN-reachable by default. Default
# to loopback-only and require an explicit opt-in (HOST env var) to widen it.
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    host = os.environ.get("HOST", "127.0.0.1")

    # AUDIT_FINDINGS.md 1.6: SECRET_KEY still being the insecure default is
    # merely a loud warning (see ez_kea/__init__.py) when bound to loopback,
    # but refuse to start entirely if it's still "dev" AND the operator is
    # asking to bind somewhere reachable off-box — that combination is what
    # turns "no auth yet" into "trivially forgeable CSRF tokens reachable
    # from the network."
    secret_key_is_default = app.config.get("SECRET_KEY") == "dev"
    if host not in _LOOPBACK_HOSTS and secret_key_is_default:
        print(
            "Refusing to start: SECRET_KEY is still the insecure default ('dev') and "
            f"HOST={host!r} is not loopback. Set a strong, random SECRET_KEY environment "
            "variable before binding EZ-Kea to a non-local address.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Serve using waitress for production-like local testing
    serve(app, host=host, port=port)
