# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
ez_kea/routes/ha.py

Configure ISC-Kea's High Availability hook (libdhcp_ha.so) for the DHCPv4
and DHCPv6 daemons, and check live HA status via each daemon's control
socket. See ez_kea/core/ha_manager.py and ez_kea/core/kea_ctrl.py for the
underlying config-editing and control-channel logic.

EZ-KEA edits one server and keeps its partners in step: a peer with a
Control API URL is set up once with a bootstrap script, after which Apply
pushes every change to it (core/ha_sync.py). A peer without one can still be
loaded by hand from peer_config_download.
"""
import json
from typing import Union
from flask_login import login_required
from flask import Blueprint, render_template, request, redirect, url_for, current_app, flash, jsonify, abort
from werkzeug.wrappers import Response

from ..core.config_manager import load_json, save_kea_config, with_config_lock, _DEFAULT_KEA6_CONFIG
from ..core.ha_manager import (
    find_ha_hook, get_ha_params, set_ha_config, remove_ha_config, parse_ha_form,
    validate_ha_against_config, peer_config, DEFAULT_HA_LIBRARY_PATH,
)
from ..core.kea_ctrl import send_command, find_unix_socket_path, ControlChannelError
from ..core import ha_sync

ha_bp = Blueprint('ha', __name__)


@ha_bp.route("/high-availability")
@login_required
def high_availability() -> str:
    """Render the High Availability configuration page for DHCPv4 and DHCPv6."""
    config4 = load_json(current_app.config["DHCP_CONFIG_FILE"])
    config6 = load_json(current_app.config["DHCP6_CONFIG_FILE"], default=_DEFAULT_KEA6_CONFIG)
    hook4 = find_ha_hook(config4, "Dhcp4")
    hook6 = find_ha_hook(config6, "Dhcp6")
    return render_template(
        "high_availability.html",
        ha4=get_ha_params(config4, "Dhcp4"),
        ha4_library=hook4.get("library") if hook4 else DEFAULT_HA_LIBRARY_PATH,
        ha6=get_ha_params(config6, "Dhcp6"),
        ha6_library=hook6.get("library") if hook6 else DEFAULT_HA_LIBRARY_PATH,
        default_library=DEFAULT_HA_LIBRARY_PATH,
        api4=ha_sync.get_peer_apis("Dhcp4"),
        api6=ha_sync.get_peer_apis("Dhcp6"),
        sync_auth=ha_sync.get_auth(),
    )


def _save_ha(dhcp_key: str, config_file: str) -> Response:
    default = _DEFAULT_KEA6_CONFIG if dhcp_key == "Dhcp6" else None
    if request.form.get("ha-enabled") != "on":
        config = load_json(config_file, default=default)
        remove_ha_config(config, dhcp_key)
        save_kea_config(config, config_file, current_app.config["BACKUP_DIR"])
        flash(f"High Availability disabled for {dhcp_key}.", "info")
        return redirect(url_for("main.ha.high_availability"))

    result, errors = parse_ha_form(request.form)
    if errors:
        for e in errors:
            flash(e, "danger")
        return redirect(url_for("main.ha.high_availability"))

    library_path, ha_params = result
    config = load_json(config_file, default=default)
    errors = validate_ha_against_config(config, ha_params, dhcp_key)
    if errors:
        for e in errors:
            flash(e, "danger")
        return redirect(url_for("main.ha.high_availability"))
    apis, errors = ha_sync.parse_peer_api_form(request.form, ha_params)
    if errors:
        for e in errors:
            flash(e, "danger")
        return redirect(url_for("main.ha.high_availability"))
    set_ha_config(config, library_path, ha_params, dhcp_key)
    save_kea_config(config, config_file, current_app.config["BACKUP_DIR"])
    ha_sync.save_peer_apis(dhcp_key, apis)
    others = [p["name"] for p in ha_params["peers"] if p["name"] != ha_params["this-server-name"]]
    managed = [n for n in others if n in apis]
    manual = [n for n in others if n not in apis]
    message = f"High Availability configuration saved for {dhcp_key}. Apply Changes loads it here"
    message += f" and pushes it to {', '.join(managed)}." if managed else "."
    if manual:
        message += (f" {', '.join(manual)} has no Control API URL, so load its config there by hand "
                    f"(Download Peer Config below), or add the URL and run its one-time setup script.")
    flash(message, "success")
    return redirect(url_for("main.ha.high_availability"))


@ha_bp.route("/save-ha-config", methods=["POST"])
@login_required
@with_config_lock()
def save_ha_config() -> Response:
    """Save the DHCPv4 High Availability hook configuration."""
    return _save_ha("Dhcp4", current_app.config["DHCP_CONFIG_FILE"])


@ha_bp.route("/save-ha-config6", methods=["POST"])
@login_required
@with_config_lock("DHCP6_CONFIG_FILE")
def save_ha_config6() -> Response:
    """Save the DHCPv6 High Availability hook configuration."""
    return _save_ha("Dhcp6", current_app.config["DHCP6_CONFIG_FILE"])


@ha_bp.route("/high-availability/peer-config/<version>/<peer_name>")
@login_required
def peer_config_download(version: str, peer_name: str) -> Response:
    """
    This server's current config, rewritten for the named peer (only
    this-server-name changes), as a JSON download, for a peer EZ-KEA doesn't
    push to (no Control API URL, or a Kea 2.x peer with no HTTP API).
    """
    if version not in ("4", "6"):
        abort(404)
    dhcp_key = f"Dhcp{version}"
    config_file = current_app.config["DHCP6_CONFIG_FILE" if version == "6" else "DHCP_CONFIG_FILE"]
    config = load_json(config_file, default=_DEFAULT_KEA6_CONFIG if version == "6" else None)
    exported = peer_config(config, dhcp_key, peer_name)
    if exported is None:
        abort(404)
    response = current_app.response_class(json.dumps(exported, indent=2) + "\n", mimetype="application/json")
    response.headers["Content-Disposition"] = f'attachment; filename="kea-dhcp{version}.{peer_name}.conf"'
    return response


@ha_bp.route("/high-availability/bootstrap/<version>/<peer_name>")
@login_required
def peer_bootstrap_download(version: str, peer_name: str) -> Response:
    """
    One-time setup script for a managed peer: installs its config plus a Kea
    control API with EZ-KEA's credentials, then reloads Kea. After that,
    Apply pushes every change to it.
    """
    if version not in ("4", "6"):
        abort(404)
    dhcp_key = f"Dhcp{version}"
    api = ha_sync.get_peer_apis(dhcp_key).get(peer_name, {}).get("api-url")
    if not api:
        abort(404)
    config_file = current_app.config["DHCP6_CONFIG_FILE" if version == "6" else "DHCP_CONFIG_FILE"]
    config = load_json(config_file, default=_DEFAULT_KEA6_CONFIG if version == "6" else None)
    script = ha_sync.bootstrap_script(config, dhcp_key, peer_name, api)
    if script is None:
        abort(404)
    response = current_app.response_class(script, mimetype="text/x-shellscript")
    response.headers["Content-Disposition"] = f'attachment; filename="ez-kea-bootstrap-{peer_name}-v{version}.sh"'
    response.headers["Cache-Control"] = "no-store"
    return response


@ha_bp.route("/high-availability/sync-settings", methods=["POST"])
@login_required
def save_sync_settings() -> Response:
    """Credentials (and an optional CA file for https) EZ-KEA uses on peers' control APIs."""
    username = (request.form.get("sync-username") or "").strip()
    password = request.form.get("sync-password") or ""
    ca_file = (request.form.get("sync-ca-file") or "").strip()
    if username and not all(c.isalnum() or c in "._-" for c in username):
        flash("API username may only contain letters, digits, '.', '_' and '-'.", "danger")
        return redirect(url_for("main.ha.high_availability"))
    if password and len(password) < 12:
        flash("API password must be at least 12 characters.", "danger")
        return redirect(url_for("main.ha.high_availability"))
    ha_sync.save_auth(username, password, ca_file)
    flash("Peer API settings saved. If you changed the username or password, run each peer's "
          "setup script again so the peer accepts them.", "success")
    return redirect(url_for("main.ha.high_availability"))


@ha_bp.route("/api/ha-sync-status/<version>")
@login_required
def api_ha_sync_status(version: str) -> Response:
    """Whether each managed peer runs the config EZ-KEA last pushed to it."""
    if version not in ("4", "6"):
        abort(404)
    dhcp_key = f"Dhcp{version}"
    config_file = current_app.config["DHCP6_CONFIG_FILE" if version == "6" else "DHCP_CONFIG_FILE"]
    config = load_json(config_file, default=_DEFAULT_KEA6_CONFIG if version == "6" else None)
    return jsonify({"peers": ha_sync.sync_status(config, dhcp_key)})


def _ha_status_response(config_file: str, dhcp_key: str) -> Response:
    config = load_json(config_file, default=_DEFAULT_KEA6_CONFIG if dhcp_key == "Dhcp6" else None)
    socket_path = find_unix_socket_path(config, dhcp_key)
    try:
        response = send_command(socket_path, "ha-heartbeat")
    except ControlChannelError as e:
        return jsonify({"error": str(e)}), 502

    if response.get("result") != 0:
        return jsonify({"error": response.get("text", "Command failed.")}), 502

    return jsonify({"message": response.get("text", "OK"), "state": response.get("arguments", {})})


@ha_bp.route("/api/ha-status")
@login_required
def api_ha_status() -> Response:
    """Live DHCPv4 HA status via the running daemon's control socket (ha-heartbeat)."""
    return _ha_status_response(current_app.config["DHCP_CONFIG_FILE"], "Dhcp4")


@ha_bp.route("/api/ha-status6")
@login_required
def api_ha_status6() -> Response:
    """Live DHCPv6 HA status via the running daemon's control socket (ha-heartbeat)."""
    return _ha_status_response(current_app.config["DHCP6_CONFIG_FILE"], "Dhcp6")
