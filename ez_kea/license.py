"""
ez_kea/license.py

RSA-signed license validation for EZ-Kea.

Free tier: all features, up to 100 active DHCP leases.
Licensed tier: unlimited leases (or whatever max_leases the license encodes).

License key format: EZK1.<base64url-payload>.<base64url-signature>

The payload is a JSON blob signed with a 2048-bit RSA private key held by
the vendor. The public key embedded here is EZ-Kea specific — it was
generated fresh for this project and is not shared with any other product.

Grace period logic:
  When the active lease count first crosses 100 (free-tier limit) the grace
  period starts: a banner is shown for 7 days, after which all write
  operations (save config, etc.) are blocked until a valid license is entered.
"""
import base64
import json
from datetime import date, datetime, timedelta
from functools import wraps

from flask import current_app, flash, jsonify, redirect, request, url_for
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# ── EZ-Kea RSA-2048 public key ──────────────────────────────────────────────
# Generated exclusively for this project.  The matching private key is kept
# offline by the vendor and is NEVER distributed with the application.
_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyBElRJJJ38CPasr0FH6P
xdNGUkCMxjNCqCDyY2uqlBHGVn5iSehFnvVN7HAmfgsfV5F21R9EFjQlKljbyl/h
73jiz53VQJhB6NMj65a7j+wpxR9zH1KUDvHFAntnNPYXoNGmeCxe36BQvk9q/lDv
E6CQMm1ewYdtnE6YKoVWow2e1uwm+BgOtMI4LkVd15EQRxQXJb6ZGcoNUR3zjj4p
WBoDNi/ogYsfK7CMpeCmHJSE6NM8SuIdy2136mr6Q2uO9kt86qU4pr6wmFlKEbQz
7FLsA7p85XCUxRVpdKcutSJU2SZy7uG0jQst+ZwPh+AlYaZDvuKfsXw+GlZA/WUK
0QIDAQAB
-----END PUBLIC KEY-----"""

_public_key = serialization.load_pem_public_key(_PUBLIC_KEY_PEM)

LICENSE_PREFIX = "EZK1."

# Free-tier lease limit — at or below this, no license required.
FREE_TIER_LEASE_LIMIT = 100

# Number of days of grace period once the free-tier limit is first exceeded.
GRACE_PERIOD_DAYS = 7


def parse_license(key_str: str) -> dict:
    """Parse and cryptographically verify a license key string.

    Args:
        key_str: The raw license key string.

    Returns:
        A dict with:
          valid (bool), error (str|None), license_id, licensee, email,
          issued, expires, days_remaining, max_leases, features.
    """
    key_str = (key_str or "").strip()
    if not key_str:
        return {"valid": False, "error": "No license key provided"}

    if not key_str.startswith(LICENSE_PREFIX):
        return {"valid": False, "error": "Invalid license format"}

    body = key_str[len(LICENSE_PREFIX):]
    parts = body.split(".")
    if len(parts) != 2:
        return {"valid": False, "error": "Malformed license key"}

    payload_b64, sig_b64 = parts
    try:
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + "==")
        sig_bytes     = base64.urlsafe_b64decode(sig_b64 + "==")
    except Exception:
        return {"valid": False, "error": "Could not decode license key"}

    try:
        _public_key.verify(sig_bytes, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return {"valid": False, "error": "License signature is invalid"}
    except Exception as e:
        return {"valid": False, "error": f"Signature verification error: {e}"}

    try:
        payload = json.loads(payload_bytes)
    except Exception:
        return {"valid": False, "error": "License payload is corrupt"}

    expires = date.fromisoformat(payload.get("expires", "1970-01-01"))
    today   = date.today()
    days_remaining = (expires - today).days

    return {
        "valid":          days_remaining > 0,
        "error":          None if days_remaining > 0 else "License has expired",
        "license_id":     payload.get("id", ""),
        "licensee":       payload.get("licensee", ""),
        "email":          payload.get("email", ""),
        "issued":         payload.get("issued", ""),
        "expires":        payload.get("expires", ""),
        "days_remaining": days_remaining,
        "max_leases":     payload.get("max_leases", 0),   # 0 = unlimited
        "features":       payload.get("features", []),
    }


def get_license() -> dict:
    """Load the stored license key from the DB and parse it.

    Safe to call from anywhere; returns an invalid license dict if the DB
    is not yet initialised or no key has been entered.
    """
    try:
        from .models import SystemSetting
        row = SystemSetting.query.get("license_key")
        key_str = row.value if row else ""
        return parse_license(key_str)
    except Exception:
        return {"valid": False, "error": "License not configured"}


def is_licensed() -> bool:
    """Return True if a valid, unexpired license is stored in the database."""
    return get_license().get("valid", False)


def get_grace_period_start() -> datetime | None:
    """Return when the grace period started (i.e. when the free tier was first
    exceeded), or None if it hasn't started yet."""
    try:
        from .models import SystemSetting
        row = SystemSetting.query.get("grace_period_start")
        if row and row.value:
            return datetime.fromisoformat(row.value)
    except Exception:
        pass
    return None


def set_grace_period_start(dt: datetime) -> None:
    """Record the start of the grace period in the database.

    Args:
        dt: The datetime when the grace period began.
    """
    try:
        from .models import SystemSetting
        from . import db
        row = SystemSetting.query.get("grace_period_start")
        if row is None:
            row = SystemSetting(key="grace_period_start", value=dt.isoformat())
            db.session.add(row)
        else:
            row.value = dt.isoformat()
        db.session.commit()
    except Exception:
        pass


def clear_grace_period() -> None:
    """Clear the stored grace period start (called when a valid license is entered)."""
    try:
        from .models import SystemSetting
        from . import db
        row = SystemSetting.query.get("grace_period_start")
        if row:
            db.session.delete(row)
            db.session.commit()
    except Exception:
        pass


def check_lease_limit(active_lease_count: int) -> dict:
    """Evaluate the current lease count against the free-tier / licensed limit.

    Returns a status dict:
      status: "ok" | "grace" | "expired" | "blocked"
      grace_days_remaining: int (only meaningful when status == "grace")
      message: str

    Lifecycle:
      - Unlicensed, leases <= 100  → "ok"   (free tier, no action needed)
      - Unlicensed, leases >  100, within grace window → "grace" (show banner)
      - Unlicensed, leases >  100, grace window elapsed → "blocked" (write lock)
      - Valid license present       → "ok"   (licensed, limit from key or unlimited)

    Args:
        active_lease_count: Number of currently active DHCP leases.

    Returns:
        dict with keys: status, grace_days_remaining, message.
    """
    lic = get_license()

    if lic.get("valid"):
        max_leases = lic.get("max_leases", 0)
        if max_leases == 0 or active_lease_count <= max_leases:
            clear_grace_period()
            return {"status": "ok", "grace_days_remaining": 0, "message": ""}
        else:
            return {
                "status": "blocked",
                "grace_days_remaining": 0,
                "message": (
                    f"Your license allows {max_leases} active leases but "
                    f"{active_lease_count} are currently active. "
                    "Please contact your administrator."
                ),
            }

    # No valid license — apply free-tier rules
    if active_lease_count <= FREE_TIER_LEASE_LIMIT:
        return {"status": "ok", "grace_days_remaining": 0, "message": ""}

    # Over the free-tier limit — start or check the grace period
    grace_start = get_grace_period_start()
    now = datetime.utcnow()
    if grace_start is None:
        set_grace_period_start(now)
        grace_start = now

    grace_end = grace_start + timedelta(days=GRACE_PERIOD_DAYS)
    if now < grace_end:
        days_left = (grace_end - now).days
        return {
            "status": "grace",
            "grace_days_remaining": max(days_left, 1),
            "message": (
                f"You have {active_lease_count} active leases — the free tier "
                f"limit is {FREE_TIER_LEASE_LIMIT}. EZ-Kea will require a "
                f"commercial license in {days_left} day{'s' if days_left != 1 else ''}."
            ),
        }
    else:
        return {
            "status": "blocked",
            "grace_days_remaining": 0,
            "message": (
                f"Your installation has exceeded {FREE_TIER_LEASE_LIMIT} active "
                "leases for more than 7 days. A commercial license is required "
                "to continue making configuration changes."
            ),
        }


def is_write_blocked() -> bool:
    """True if the free-tier grace period has elapsed with no valid license.

    Reads the live lease count off disk on every call rather than trusting a
    cached value, since this is the actual enforcement point (unlike the
    banner in base.html's context processor, which is just informational).
    """
    from .core.validation import get_active_leases
    try:
        active = len(get_active_leases(current_app.config.get("DHCP_LEASES_FILE", "")))
    except Exception:
        return False
    return check_lease_limit(active).get("status") == "blocked"


def license_gate(view):
    """Route decorator: blocks POST/PUT/DELETE/PATCH requests once
    is_write_blocked() is true. GET/HEAD always pass through, so existing
    configuration stays viewable even past the grace period — only routes
    that create/modify/delete configuration are gated. Apply this alongside
    (not instead of) @login_required on any route that writes config.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.method not in ("GET", "HEAD") and is_write_blocked():
            message = (
                "Configuration changes are locked: this installation has "
                "exceeded the free-tier lease limit and its 7-day grace period. "
                "A commercial license is required to continue. Contact your "
                "administrator."
            )
            if request.path.startswith("/api/"):
                return jsonify({"error": message}), 402
            flash(message, "error")
            return redirect(request.referrer or url_for("main.system.index"))
        return view(*args, **kwargs)
    return wrapped
