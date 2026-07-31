# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
ez_kea/mailer.py

Minimal, dependency-free SMTP mailer for EZ-KEA. Settings are stored as
key/value rows in the existing SystemSetting table (same table/pattern
license.py uses for license_key) -- no new table needed.

Settings keys used (all read via get_settings_dict()):
  smtp_host, smtp_port, smtp_username, smtp_password, smtp_from, smtp_tls,
  company_name, app_url
"""
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


def get_settings_dict() -> dict:
    """Load every SystemSetting row as a flat {key: value} dict.

    Safe to call from anywhere; returns an empty dict if the DB isn't
    reachable (mirrors the try/except pattern used throughout license.py).
    """
    try:
        from .models import SystemSetting
        rows = SystemSetting.query.all()
        return {r.key: r.value for r in rows}
    except Exception:
        return {}


def _set_setting(key: str, value: str) -> None:
    """Write a single SystemSetting row, matching the get-or-create pattern
    used by license.py to persist the license key."""
    from . import db
    from .models import SystemSetting
    row = SystemSetting.query.get(key)
    if row is None:
        row = SystemSetting(key=key, value=value)
        db.session.add(row)
    else:
        row.value = value


def save_smtp_settings(form: dict) -> None:
    """Persist the admin-facing SMTP settings fields from a submitted form
    dict. Commits the session. Password is only overwritten when a new,
    non-blank value is supplied (a blank/masked submission means "unchanged"),
    matching the private-key-field convention in security-audit's settings_bp.
    """
    from . import db
    fields = ("smtp_host", "smtp_port", "smtp_username", "smtp_from",
              "company_name", "app_url")
    for key in fields:
        if key in form:
            _set_setting(key, (form.get(key) or "").strip())
    if form.get("smtp_password"):
        _set_setting("smtp_password", form["smtp_password"].strip())
    _set_setting("smtp_tls", "true" if form.get("smtp_tls") else "false")
    db.session.commit()


def _smtp_connect(settings: dict):
    """
    Open and return an authenticated SMTP connection.
    Port 465  -> direct SMTP_SSL (ignore the STARTTLS checkbox).
    All other ports -> plain SMTP + STARTTLS if the checkbox is on.
    Raises on any connection or auth failure.
    """
    host = settings.get("smtp_host", "").strip()
    port = int(settings.get("smtp_port", 587) or 587)
    user = settings.get("smtp_username", "").strip()
    pwd = settings.get("smtp_password", "").strip()
    tls = settings.get("smtp_tls", "true").lower() == "true"

    if port == 465:
        server = smtplib.SMTP_SSL(host, port, timeout=15)
        server.ehlo()
    else:
        server = smtplib.SMTP(host, port, timeout=15)
        server.ehlo()
        if tls:
            server.starttls()
            server.ehlo()  # re-identify after TLS upgrade so AUTH is advertised

    if user and pwd:
        server.login(user, pwd)
    return server


def send_password_reset_email(user, reset_url: str, settings: dict) -> tuple[bool, str]:
    """Email a self-service password-reset link. Not gated behind is_licensed()
    -- nothing in EZ-KEA is (see license.py) -- and account recovery is the
    last thing that should be: a locked-out admin on an unlicensed install
    would otherwise have no way back in at all.
    """
    smtp_host = settings.get("smtp_host", "").strip()
    if not smtp_host:
        return False, "SMTP is not configured in Settings."

    smtp_from = settings.get("smtp_from", "").strip() or settings.get("smtp_username", "").strip()
    company = settings.get("company_name", "EZ-KEA")

    subject = f"[{company}] Password Reset Request"
    body_html = f"""
<html><body style="font-family:sans-serif;color:#1e293b;">
<h2 style="color:#1d4ed8;">Password Reset</h2>
<p>A password reset was requested for the account <strong>{user.username}</strong>.</p>
<p style="margin-top:16px;"><a href="{reset_url}" style="background:#0f2d4a;color:white;padding:10px 20px;text-decoration:none;border-radius:6px;font-weight:bold;">Reset Password</a></p>
<p style="color:#64748b;font-size:13px;margin-top:16px;">This link expires in 60 minutes. If you didn't request this, you can safely ignore this email -- your password won't change unless you click the link above.</p>
<p style="color:#94a3b8;font-size:12px;margin-top:24px;">Sent by {company}.</p>
</body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = user.email
    msg.attach(MIMEText(body_html, "html"))

    try:
        server = _smtp_connect(settings)
        server.sendmail(smtp_from, [user.email], msg.as_string())
        server.quit()
        logger.info("Password reset email sent to %s for user %s", user.email, user.username)
        return True, f"Reset email sent to {user.email}."
    except Exception as e:
        logger.error("Failed to send password reset email to %s: %s", user.email, e)
        return False, str(e)


def test_smtp(settings: dict) -> tuple[bool, str]:
    """Test an SMTP connection using the supplied settings dict (which may
    be posted-but-unsaved form values). Returns (success, message)."""
    smtp_host = settings.get("smtp_host", "").strip()
    if not smtp_host:
        return False, "SMTP host is not configured."
    smtp_port = int(settings.get("smtp_port", 587) or 587)
    try:
        server = _smtp_connect(settings)
        server.quit()
        return True, f"Connected to {smtp_host}:{smtp_port} successfully."
    except Exception as e:
        return False, str(e)
