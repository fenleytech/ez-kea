# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
ez_kea/routes/ha.py

Configure ISC-Kea's High Availability hook (libdhcp_ha.so) for the DHCPv4
and DHCPv6 daemons, and check live HA status via each daemon's control
socket. See ez_kea/core/ha_manager.py and ez_kea/core/kea_ctrl.py for the
underlying config-editing and control-channel logic.
"""
from typing import Union
from flask_login import login_required
from flask import Blueprint, render_template, request, redirect, url_for, current_app, flash, jsonify
from werkzeug.wrappers import Response

from ..core.config_manager import load_json, save_kea_config, with_config_lock
from ..core.ha_manager import (
    find_ha_hook, get_ha_params, set_ha_config, remove_ha_config, parse_ha_form,
    DEFAULT_HA_LIBRARY_PATH,
)
from ..core.kea_ctrl import send_command, find_unix_socket_path, ControlChannelError

ha_bp = Blueprint('ha', __name__)


@ha_bp.route("/high-availability")
@login_required
def high_availability() -> str:
    """Render the High Availability configuration page for DHCPv4 and DHCPv6."""
    config4 = load_json(current_app.config["DHCP_CONFIG_FILE"])
    config6 = load_json(current_app.config["DHCP6_CONFIG_FILE"])
    hook4 = find_ha_hook(config4, "Dhcp4")
    hook6 = find_ha_hook(config6, "Dhcp6")
    return render_template(
        "high_availability.html",
        ha4=get_ha_params(config4, "Dhcp4"),
        ha4_library=hook4.get("library") if hook4 else DEFAULT_HA_LIBRARY_PATH,
        ha6=get_ha_params(config6, "Dhcp6"),
        ha6_library=hook6.get("library") if hook6 else DEFAULT_HA_LIBRARY_PATH,
        default_library=DEFAULT_HA_LIBRARY_PATH,
    )


def _save_ha(dhcp_key: str, config_file: str) -> Response:
    if request.form.get("ha-enabled") != "on":
        config = load_json(config_file)
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
    config = load_json(config_file)
    set_ha_config(config, library_path, ha_params, dhcp_key)
    save_kea_config(config, config_file, current_app.config["BACKUP_DIR"])
    flash(f"High Availability configuration saved for {dhcp_key}.", "success")
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


def _ha_status_response(config_file: str, dhcp_key: str) -> Response:
    config = load_json(config_file)
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
