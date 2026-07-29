"""ez_kea/auth.py — User authentication blueprint."""
import io, json, base64, re, secrets, threading, time
from datetime import datetime, timedelta

import pyotp, qrcode
from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, session, send_file, abort, current_app, jsonify)
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, login_manager
from .models import User, SystemSetting

auth_bp = Blueprint("auth", __name__)

# ── Rate limiting ─────────────────────────────────────────────────────────────
_login_attempts = {}
_login_lock = threading.Lock()
MAX_ATTEMPTS = 4
LOCKOUT_WINDOW = 900
LOCKOUT_DURATION = 300
MIN_PASSWORD_LEN = 15
_RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def _record_failure(key):
    now = time.time()
    with _login_lock:
        e = _login_attempts.get(key)
        if not e or now - e["first"] > LOCKOUT_WINDOW:
            e = {"count": 0, "first": now, "locked_until": 0}
        e["count"] += 1
        if e["count"] >= MAX_ATTEMPTS:
            e["locked_until"] = now + LOCKOUT_DURATION
        _login_attempts[key] = e
        return e["count"]


def _is_locked(key):
    with _login_lock:
        e = _login_attempts.get(key)
        if not e or not e["locked_until"]:
            return False
        if time.time() < e["locked_until"]:
            return True
        del _login_attempts[key]
        return False


def _clear(key):
    with _login_lock:
        _login_attempts.pop(key, None)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def _validate_password(pw):
    if len(pw) < MIN_PASSWORD_LEN:
        return f"Password must be at least {MIN_PASSWORD_LEN} characters."
    return None


def _validate_username(username, exclude_uid=None):
    if not username:
        return "Username is required."
    if username.lower() == "admin":
        return "Choose a username other than 'admin'."
    ex = User.query.filter_by(username=username).first()
    if ex and ex.id != exclude_uid:
        return f"Username '{username}' is already taken."
    return None


def _qr_uri(secret, username):
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="EZ-Kea")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def _gen_recovery_codes(user):
    codes, hashes = [], []
    for _ in range(8):
        raw = "-".join("".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(5)) for _ in range(2))
        codes.append(raw)
        hashes.append(generate_password_hash(raw))
    user.recovery_codes = json.dumps(hashes)
    return codes


def _redeem_recovery(user, code):
    code = (code or "").strip().upper()
    if not code:
        return False
    try:
        hashes = json.loads(user.recovery_codes or "[]")
    except ValueError:
        return False
    for h in hashes:
        if check_password_hash(h, code):
            hashes.remove(h)
            user.recovery_codes = json.dumps(hashes)
            return True
    return False


RESET_TTL = 60


def _gen_reset_token(user):
    token = secrets.token_urlsafe(32)
    user.reset_token_hash = generate_password_hash(token)
    user.reset_token_expires = datetime.utcnow() + timedelta(minutes=RESET_TTL)
    return token


def _valid_reset(user, token):
    if not user or not user.reset_token_hash or not user.reset_token_expires:
        return False
    if datetime.utcnow() > user.reset_token_expires:
        return False
    return check_password_hash(user.reset_token_hash, token or "")


# ── Login ──────────────────────────────────────────────────────────────────────
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.system.index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))
        ip_key, u_key = f"ip:{request.remote_addr}", f"user:{username.lower()}"
        if _is_locked(ip_key) or _is_locked(u_key):
            flash("Too many failed attempts. Try again in a few minutes.", "error")
            return render_template("login.html")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            _clear(ip_key); _clear(u_key)
            if user.must_change_password or user.must_change_username:
                session["pending_setup_uid"] = user.id
                session["pending_setup_remember"] = remember
                return redirect(url_for("auth.account_setup"))
            if user.totp_enabled:
                session["pending_2fa_uid"] = user.id
                session["pending_2fa_remember"] = remember
                return redirect(url_for("auth.login_2fa"))
            if user.totp_required:
                session["pending_2fa_uid"] = user.id
                session["pending_2fa_remember"] = remember
                return redirect(url_for("auth.login_2fa_setup"))
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=remember)
            return redirect(request.args.get("next") or url_for("main.system.index"))
        count = max(_record_failure(ip_key), _record_failure(u_key))
        rem = MAX_ATTEMPTS - count
        if rem > 0:
            flash(f"Invalid credentials. {rem} attempt{'s' if rem!=1 else ''} remaining.", "error")
        else:
            flash("Too many failed attempts. Try again in a few minutes.", "error")
    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


# ── Account setup (force credential change) ────────────────────────────────────
@auth_bp.route("/login/account-setup", methods=["GET", "POST"])
def account_setup():
    uid = session.get("pending_setup_uid")
    user = db.session.get(User, uid) if uid else None
    if not user or not (user.must_change_password or user.must_change_username):
        session.pop("pending_setup_uid", None)
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        new_username = request.form.get("username", "").strip() if user.must_change_username else user.username
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")
        err = None
        if user.must_change_username:
            err = _validate_username(new_username, exclude_uid=user.id)
        if not err and user.must_change_password:
            err = _validate_password(new_pw) or (None if new_pw == confirm_pw else "Passwords do not match.")
        if err:
            flash(err, "error")
        else:
            if user.must_change_username: user.username = new_username
            if user.must_change_password: user.password_hash = generate_password_hash(new_pw)
            user.must_change_username = user.must_change_password = False
            remember = session.pop("pending_setup_remember", False)
            session.pop("pending_setup_uid", None)
            if user.totp_enabled:
                db.session.commit()
                session["pending_2fa_uid"] = user.id
                session["pending_2fa_remember"] = remember
                return redirect(url_for("auth.login_2fa"))
            if user.totp_required:
                db.session.commit()
                session["pending_2fa_uid"] = user.id
                session["pending_2fa_remember"] = remember
                return redirect(url_for("auth.login_2fa_setup"))
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=remember)
            return redirect(url_for("main.system.index"))
    return render_template("login_account_setup.html",
                           username=user.username,
                           need_username=user.must_change_username,
                           need_password=user.must_change_password,
                           min_length=MIN_PASSWORD_LEN)


# ── 2FA login ──────────────────────────────────────────────────────────────────
@auth_bp.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    uid = session.get("pending_2fa_uid")
    user = db.session.get(User, uid) if uid else None
    if not user or not user.totp_enabled:
        session.pop("pending_2fa_uid", None)
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        key = f"2fa:{user.id}"
        if _is_locked(key):
            flash("Too many failed codes. Try again in a few minutes.", "error")
            return render_template("login_2fa.html", username=user.username)
        code = (request.form.get("code") or "").strip().replace(" ", "")
        if pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
            _clear(key)
            remember = session.pop("pending_2fa_remember", False)
            session.pop("pending_2fa_uid", None)
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=remember)
            return redirect(url_for("main.system.index"))
        if _redeem_recovery(user, code):
            _clear(key)
            remaining = len(json.loads(user.recovery_codes or "[]"))
            remember = session.pop("pending_2fa_remember", False)
            session.pop("pending_2fa_uid", None)
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=remember)
            msg = (f"Logged in with a recovery code — {remaining} left." if remaining
                   else "Used last recovery code — re-enroll 2FA to generate new ones.")
            flash(msg, "success" if remaining else "error")
            return redirect(url_for("main.system.index"))
        count = _record_failure(key)
        rem = MAX_ATTEMPTS - count
        flash(f"Invalid code. {rem} attempt{'s' if rem!=1 else ''} remaining." if rem > 0
              else "Too many failed codes. Try again in a few minutes.", "error")
    return render_template("login_2fa.html", username=user.username)


@auth_bp.route("/login/2fa/setup", methods=["GET", "POST"])
def login_2fa_setup():
    uid = session.get("pending_2fa_uid")
    user = db.session.get(User, uid) if uid else None
    if not user or user.totp_enabled or not user.totp_required:
        return redirect(url_for("auth.login"))
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.session.commit()
    if request.method == "POST":
        k = f"2fa_setup:{user.id}"
        if _is_locked(k):
            flash("Too many failed codes. Try again later.", "error")
        else:
            code = (request.form.get("code") or "").strip().replace(" ", "")
            if pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
                _clear(k)
                user.totp_enabled = True
                user.totp_required = False
                remember = session.pop("pending_2fa_remember", False)
                session.pop("pending_2fa_uid", None)
                if user.is_break_glass:
                    codes = _gen_recovery_codes(user)
                    db.session.commit()
                    session["pending_recovery_uid"] = user.id
                    session["pending_recovery_codes"] = codes
                    session["pending_recovery_remember"] = remember
                    return redirect(url_for("auth.login_recovery_codes"))
                user.last_login = datetime.utcnow()
                db.session.commit()
                login_user(user, remember=remember)
                return redirect(url_for("main.system.index"))
            count = _record_failure(k)
            rem = MAX_ATTEMPTS - count
            flash(f"Invalid code. {rem} attempt{'s' if rem!=1 else ''} remaining." if rem > 0
                  else "Too many failed codes. Try again later.", "error")
    return render_template("login_2fa_setup.html", username=user.username,
                           totp_qr=_qr_uri(user.totp_secret, user.username),
                           totp_secret=user.totp_secret)


@auth_bp.route("/login/recovery-codes", methods=["GET", "POST"])
def login_recovery_codes():
    uid = session.get("pending_recovery_uid")
    codes = session.get("pending_recovery_codes")
    user = db.session.get(User, uid) if uid else None
    if not user or not codes:
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        remember = session.pop("pending_recovery_remember", False)
        session.pop("pending_recovery_uid", None)
        session.pop("pending_recovery_codes", None)
        user.last_login = datetime.utcnow()
        db.session.commit()
        login_user(user, remember=remember)
        return redirect(url_for("main.system.index"))
    return render_template("login_recovery_codes.html", username=user.username, codes=codes)


@auth_bp.route("/login/2fa/cancel")
def login_2fa_cancel():
    for k in ("pending_2fa_uid", "pending_2fa_remember", "pending_setup_uid",
              "pending_setup_remember", "pending_recovery_uid",
              "pending_recovery_codes", "pending_recovery_remember"):
        session.pop(k, None)
    return redirect(url_for("auth.login"))


# ── Forgot / reset password ────────────────────────────────────────────────────
@auth_bp.route("/login/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        identifier = (request.form.get("identifier") or "").strip()
        user = User.query.filter((User.username == identifier) | (User.email == identifier)).first() if identifier else None
        if user and (user.email or "").strip():
            token = _gen_reset_token(user)
            db.session.commit()
            reset_url = url_for("auth.reset_password", uid=user.id, token=token, _external=True)
            from . import mailer
            settings = mailer.get_settings_dict()
            if settings.get("smtp_host", "").strip():
                ok, msg = mailer.send_password_reset_email(user, reset_url, settings)
                if not ok:
                    # SMTP is configured but sending failed -- still surface the
                    # link in the log so a self-hosted admin isn't locked out.
                    current_app.logger.warning("Password reset email failed for %s (%s); link: %s",
                                                user.username, msg, reset_url)
            else:
                # No SMTP configured -- fall back to the previous behavior so a
                # self-hosted admin without mail set up can still see the link.
                current_app.logger.info("Password reset link for %s: %s", user.username, reset_url)
        flash("If that account has an email on file, a reset link has been sent.", "success")
        return redirect(url_for("auth.login"))
    return render_template("login_forgot_password.html")


@auth_bp.route("/login/reset-password/<int:uid>/<token>", methods=["GET", "POST"])
def reset_password(uid, token):
    user = db.session.get(User, uid)
    if not _valid_reset(user, token):
        flash("This reset link is invalid or has expired.", "error")
        return redirect(url_for("auth.forgot_password"))
    if request.method == "POST":
        new_pw = request.form.get("password", "").strip()
        err = _validate_password(new_pw)
        if err:
            flash(err, "error")
            return render_template("login_reset_password.html", uid=uid, token=token)
        user.password_hash = generate_password_hash(new_pw)
        user.must_change_password = False
        user.reset_token_hash = user.reset_token_expires = None
        db.session.commit()
        flash("Password reset — log in with your new password.", "success")
        return redirect(url_for("auth.login"))
    return render_template("login_reset_password.html", uid=uid, token=token)


# ── User management (admin only) ───────────────────────────────────────────────
@auth_bp.route("/users")
@login_required
def users():
    if not current_user.is_admin:
        abort(403)
    all_users = User.query.order_by(User.username).all()
    return render_template("users.html", users=all_users)


@auth_bp.route("/users/create", methods=["POST"])
@login_required
def users_create():
    if not current_user.is_admin:
        abort(403)
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    email    = request.form.get("email", "").strip()
    is_admin = bool(request.form.get("is_admin"))
    err = _validate_username(username) or _validate_password(password)
    if err:
        flash(err, "error")
        return redirect(url_for("auth.users"))
    db.session.add(User(username=username,
                        password_hash=generate_password_hash(password),
                        email=email, is_admin=is_admin,
                        must_change_password=True))
    db.session.commit()
    flash(f"User '{username}' created.", "success")
    return redirect(url_for("auth.users"))


@auth_bp.route("/users/<int:uid>/delete", methods=["POST"])
@login_required
def users_delete(uid):
    if not current_user.is_admin:
        abort(403)
    if uid == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("auth.users"))
    user = db.session.get(User, uid) or abort(404)
    if user.is_break_glass:
        flash("The break-glass recovery account cannot be deleted.", "error")
        return redirect(url_for("auth.users"))
    db.session.delete(user)
    db.session.commit()
    flash(f"User '{user.username}' deleted.", "success")
    return redirect(url_for("auth.users"))


@auth_bp.route("/users/<int:uid>/reset", methods=["POST"])
@login_required
def users_reset(uid):
    if not current_user.is_admin:
        abort(403)
    user = db.session.get(User, uid) or abort(404)
    new_pw = request.form.get("password", "")
    err = _validate_password(new_pw)
    if err:
        flash(err, "error")
        return redirect(url_for("auth.users"))
    user.password_hash = generate_password_hash(new_pw)
    user.must_change_password = True
    db.session.commit()
    flash(f"Password reset for '{user.username}'.", "success")
    return redirect(url_for("auth.users"))


@auth_bp.route("/users/<int:uid>/toggle-admin", methods=["POST"])
@login_required
def users_toggle_admin(uid):
    if not current_user.is_admin:
        abort(403)
    if uid == current_user.id:
        flash("You cannot change your own admin status.", "error")
        return redirect(url_for("auth.users"))
    user = db.session.get(User, uid) or abort(404)
    if user.is_break_glass:
        flash("The break-glass account must remain an admin.", "error")
        return redirect(url_for("auth.users"))
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f"Admin {'granted' if user.is_admin else 'revoked'} for '{user.username}'.", "success")
    return redirect(url_for("auth.users"))


@auth_bp.route("/users/<int:uid>/reset-2fa", methods=["POST"])
@login_required
def users_reset_2fa(uid):
    if not current_user.is_admin:
        abort(403)
    user = db.session.get(User, uid) or abort(404)
    user.totp_enabled = False
    user.totp_secret  = ""
    user.recovery_codes = "[]"
    db.session.commit()
    flash(f"2FA reset for '{user.username}'.", "success")
    return redirect(url_for("auth.users"))


# ── Profile ────────────────────────────────────────────────────────────────────
@auth_bp.route("/profile")
@login_required
def profile():
    totp_qr = None
    if current_user.totp_secret and not current_user.totp_enabled:
        totp_qr = _qr_uri(current_user.totp_secret, current_user.username)
    recovery_codes = session.pop("show_recovery_codes", None)
    recovery_remaining = None
    if current_user.is_break_glass and current_user.totp_enabled:
        recovery_remaining = len(json.loads(current_user.recovery_codes or "[]"))
    return render_template("profile.html", totp_qr=totp_qr,
                           recovery_codes=recovery_codes,
                           recovery_remaining=recovery_remaining)


@auth_bp.route("/profile/change-password", methods=["POST"])
@login_required
def change_password():
    current_pw = request.form.get("current_password", "")
    new_pw     = request.form.get("new_password", "")
    if not check_password_hash(current_user.password_hash, current_pw):
        flash("Current password is incorrect.", "error")
    else:
        err = _validate_password(new_pw)
        if err:
            flash(err, "error")
        else:
            current_user.password_hash = generate_password_hash(new_pw)
            db.session.commit()
            flash("Password changed.", "success")
    return redirect(url_for("auth.profile"))


@auth_bp.route("/profile/2fa/setup", methods=["POST"])
@login_required
def profile_2fa_setup():
    current_user.totp_secret  = pyotp.random_base32()
    current_user.totp_enabled = False
    db.session.commit()
    return redirect(url_for("auth.profile"))


@auth_bp.route("/profile/2fa/confirm", methods=["POST"])
@login_required
def profile_2fa_confirm():
    code = (request.form.get("code") or "").strip().replace(" ", "")
    if not current_user.totp_secret:
        flash("Start 2FA setup first.", "error")
    elif pyotp.TOTP(current_user.totp_secret).verify(code, valid_window=1):
        current_user.totp_enabled = True
        if current_user.is_break_glass:
            session["show_recovery_codes"] = _gen_recovery_codes(current_user)
        db.session.commit()
        flash("Two-factor authentication enabled.", "success")
    else:
        flash("Invalid code — try again.", "error")
    return redirect(url_for("auth.profile"))


@auth_bp.route("/profile/2fa/disable", methods=["POST"])
@login_required
def profile_2fa_disable():
    password = request.form.get("password", "")
    if not check_password_hash(current_user.password_hash, password):
        flash("Incorrect password.", "error")
    else:
        current_user.totp_enabled = False
        current_user.totp_secret  = ""
        current_user.recovery_codes = "[]"
        db.session.commit()
        flash("Two-factor authentication disabled.", "success")
    return redirect(url_for("auth.profile"))


# ── License management (admin) ─────────────────────────────────────────────────
@auth_bp.route("/license", methods=["GET", "POST"])
@login_required
def license_page():
    if not current_user.is_admin:
        abort(403)
    from .license import get_license, clear_grace_period
    message = None
    if request.method == "POST":
        key_str = (request.form.get("license_key") or "").strip()
        result  = get_license.__module__ and __import__("ez_kea.license", fromlist=["parse_license"]).parse_license(key_str)
        if result.get("valid"):
            row = SystemSetting.query.get("license_key")
            if row is None:
                row = SystemSetting(key="license_key", value=key_str)
                db.session.add(row)
            else:
                row.value = key_str
            db.session.commit()
            clear_grace_period()
            flash("License activated successfully.", "success")
        else:
            flash(f"Invalid license: {result.get('error')}", "error")
        return redirect(url_for("auth.license_page"))
    lic = get_license()
    return render_template("license.html", lic=lic)


# ── Email / SMTP settings (admin) ──────────────────────────────────────────────
@auth_bp.route("/email-settings", methods=["GET", "POST"])
@login_required
def email_settings():
    if not current_user.is_admin:
        abort(403)
    from . import mailer
    if request.method == "POST":
        mailer.save_smtp_settings(request.form)
        flash("Email settings saved.", "success")
        return redirect(url_for("auth.email_settings"))
    settings = mailer.get_settings_dict()
    return render_template("email_settings.html", settings=settings)


@auth_bp.route("/email-settings/test", methods=["POST"])
@login_required
def email_settings_test():
    if not current_user.is_admin:
        abort(403)
    from . import mailer
    # Use the posted-but-unsaved form values so the admin can test before
    # saving -- same pattern as security-audit's /test-smtp route.
    posted = request.get_json() or {}
    settings = mailer.get_settings_dict()
    for key in ("smtp_host", "smtp_port", "smtp_username", "smtp_from"):
        if key in posted:
            settings[key] = posted[key]
    # A blank posted password means "use the already-saved password", not
    # "no password" -- only override when a new one was actually typed.
    if posted.get("smtp_password"):
        settings["smtp_password"] = posted["smtp_password"]
    settings["smtp_tls"] = "true" if posted.get("smtp_tls") else "false"
    ok, msg = mailer.test_smtp(settings)
    return jsonify({"ok": ok, "message": msg})
