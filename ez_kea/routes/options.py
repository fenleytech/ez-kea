# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

from typing import Any, Dict, Union, Tuple
from flask_login import login_required
from flask import Blueprint, render_template, request, redirect, url_for, current_app, flash
from werkzeug.wrappers import Response
from ..core.config_manager import load_json, save_kea_config, with_config_lock
from ..core.validation import validate_option_data
from .dhcp6 import _find_subnet6

options_bp = Blueprint('options', __name__)

@options_bp.route("/options/subnet4/<shared_network_name>/<path:subnet>", methods=["GET", "POST"])
@login_required
@with_config_lock()
def manage_subnet4_options(shared_network_name: str, subnet: str) -> Union[str, Response, Tuple[str, int]]:
    """Manage DHCP options for a given subnet within a shared network."""
    config = load_json(current_app.config["DHCP_CONFIG_FILE"])
    
    # Locate target subnet
    target_subnet = None
    for network in config.get("Dhcp4", {}).get("shared-networks", []):
         if network.get("name") == shared_network_name:
             for s in network.get("subnet4", []):
                 if s.get("subnet") == subnet:
                     target_subnet = s
                     break
             if target_subnet:
                 break

    if not target_subnet:
        return "Subnet not found", 404

    if request.method == "POST":
        option_name = request.form.get("option-name")
        option_data = request.form.get("option-data")

        if option_name and option_data:
             if not validate_option_data(option_name) or not validate_option_data(option_data):
                  flash("Option name/data contains control characters or angle brackets, which are not allowed.", "danger")
                  return redirect(url_for("main.options.manage_subnet4_options", shared_network_name=shared_network_name, subnet=subnet))

             if "option-data" not in target_subnet:
                  target_subnet["option-data"] = []

             # Check if option exists and update, else append
             updated = False
             for opt in target_subnet["option-data"]:
                  if opt.get("name") == option_name:
                       opt["data"] = option_data
                       updated = True
                       break
             if not updated:
                  target_subnet["option-data"].append({"name": option_name, "data": option_data})

             save_kea_config(config, current_app.config["DHCP_CONFIG_FILE"], current_app.config["BACKUP_DIR"])

        return redirect(url_for("main.options.manage_subnet4_options", shared_network_name=shared_network_name, subnet=subnet))

    # GET request
    options = target_subnet.get("option-data", [])
    return render_template("manage_options.html", 
                         shared_network_name=shared_network_name, 
                         subnet=subnet, 
                         options=options,
                         version="4")
                         
@options_bp.route("/options/subnet4/<shared_network_name>/<path:subnet>/delete", methods=["POST"])
@login_required
@with_config_lock()
def delete_subnet4_option(shared_network_name: str, subnet: str) -> Response:
    """Delete a DHCP option from a specific subnet in a shared network."""
    option_name = request.form.get("option-name")
    config = load_json(current_app.config["DHCP_CONFIG_FILE"])
    
    for network in config.get("Dhcp4", {}).get("shared-networks", []):
         if network.get("name") == shared_network_name:
             for s in network.get("subnet4", []):
                 if s.get("subnet") == subnet and "option-data" in s:
                     s["option-data"] = [opt for opt in s["option-data"] if opt.get("name") != option_name]
                     break
             break
             
    save_kea_config(config, current_app.config["DHCP_CONFIG_FILE"], current_app.config["BACKUP_DIR"])
    return redirect(url_for("main.options.manage_subnet4_options", shared_network_name=shared_network_name, subnet=subnet))


# ── Standalone subnet-level options (no shared-network) ──────────────────────

@options_bp.route("/options/subnet4/standalone/<path:subnet>", methods=["GET", "POST"])
@login_required
@with_config_lock()
def manage_standalone_subnet4_options(subnet: str) -> Union[str, Response, Tuple[str, int]]:
    """Options for subnets that live directly under Dhcp4 (not in a shared-network)."""
    config = load_json(current_app.config["DHCP_CONFIG_FILE"])

    target_subnet = None
    for s in config.get("Dhcp4", {}).get("subnet4", []):
        if s.get("subnet") == subnet:
            target_subnet = s
            break

    if not target_subnet:
        return "Subnet not found", 404

    if request.method == "POST":
        option_name = request.form.get("option-name")
        option_data = request.form.get("option-data")
        if option_name and option_data:
            if not validate_option_data(option_name) or not validate_option_data(option_data):
                flash("Option name/data contains control characters or angle brackets, which are not allowed.", "danger")
                return redirect(url_for("main.options.manage_standalone_subnet4_options", subnet=subnet))

            opts = target_subnet.setdefault("option-data", [])
            for opt in opts:
                if opt.get("name") == option_name:
                    opt["data"] = option_data
                    break
            else:
                opts.append({"name": option_name, "data": option_data})
            save_kea_config(config, current_app.config["DHCP_CONFIG_FILE"], current_app.config["BACKUP_DIR"])
        return redirect(url_for("main.options.manage_standalone_subnet4_options", subnet=subnet))

    options = target_subnet.get("option-data", [])
    return render_template("manage_options.html",
                           shared_network_name="(standalone)",
                           subnet=subnet,
                           options=options,
                           version="4",
                           standalone=True)


@options_bp.route("/options/subnet4/standalone/<path:subnet>/delete", methods=["POST"])
@login_required
@with_config_lock()
def delete_standalone_subnet4_option(subnet: str) -> Response:
    """Delete a DHCP option from a standalone subnet."""
    option_name = request.form.get("option-name")
    config = load_json(current_app.config["DHCP_CONFIG_FILE"])
    for s in config.get("Dhcp4", {}).get("subnet4", []):
        if s.get("subnet") == subnet and "option-data" in s:
            s["option-data"] = [o for o in s["option-data"] if o.get("name") != option_name]
            break
    save_kea_config(config, current_app.config["DHCP_CONFIG_FILE"], current_app.config["BACKUP_DIR"])
    return redirect(url_for("main.options.manage_standalone_subnet4_options", subnet=subnet))


# ── DHCPv6 subnet option-data (dns-servers, sntp-servers, domain-search, …) ──

@options_bp.route("/options/subnet6/<shared_network_name>/<path:subnet>", methods=["GET", "POST"])
@login_required
@with_config_lock("DHCP6_CONFIG_FILE")
def manage_subnet6_options(shared_network_name: str, subnet: str) -> Union[str, Response, Tuple[str, int]]:
    """Manage DHCPv6 options for a given subnet within a shared network."""
    config = load_json(current_app.config["DHCP6_CONFIG_FILE"])

    target_subnet, found_network_name = _find_subnet6(config, subnet)
    if not target_subnet or found_network_name != shared_network_name:
        return "Subnet not found", 404

    if request.method == "POST":
        option_name = request.form.get("option-name")
        option_data = request.form.get("option-data")

        if option_name and option_data:
             if not validate_option_data(option_name) or not validate_option_data(option_data):
                  flash("Option name/data contains control characters or angle brackets, which are not allowed.", "danger")
                  return redirect(url_for("main.options.manage_subnet6_options", shared_network_name=shared_network_name, subnet=subnet))

             if "option-data" not in target_subnet:
                  target_subnet["option-data"] = []

             updated = False
             for opt in target_subnet["option-data"]:
                  if opt.get("name") == option_name:
                       opt["data"] = option_data
                       updated = True
                       break
             if not updated:
                  target_subnet["option-data"].append({"name": option_name, "data": option_data})

             save_kea_config(config, current_app.config["DHCP6_CONFIG_FILE"], current_app.config["BACKUP_DIR"])

        return redirect(url_for("main.options.manage_subnet6_options", shared_network_name=shared_network_name, subnet=subnet))

    options = target_subnet.get("option-data", [])
    return render_template("manage_options.html",
                         shared_network_name=shared_network_name,
                         subnet=subnet,
                         options=options,
                         version="6")

@options_bp.route("/options/subnet6/<shared_network_name>/<path:subnet>/delete", methods=["POST"])
@login_required
@with_config_lock("DHCP6_CONFIG_FILE")
def delete_subnet6_option(shared_network_name: str, subnet: str) -> Response:
    """Delete a DHCPv6 option from a specific subnet in a shared network."""
    option_name = request.form.get("option-name")
    config = load_json(current_app.config["DHCP6_CONFIG_FILE"])

    target_subnet, found_network_name = _find_subnet6(config, subnet)
    if target_subnet and found_network_name == shared_network_name and "option-data" in target_subnet:
        target_subnet["option-data"] = [opt for opt in target_subnet["option-data"] if opt.get("name") != option_name]

    save_kea_config(config, current_app.config["DHCP6_CONFIG_FILE"], current_app.config["BACKUP_DIR"])
    return redirect(url_for("main.options.manage_subnet6_options", shared_network_name=shared_network_name, subnet=subnet))


# ── Standalone subnet6-level options (no shared-network) ─────────────────────

@options_bp.route("/options/subnet6/standalone/<path:subnet>", methods=["GET", "POST"])
@login_required
@with_config_lock("DHCP6_CONFIG_FILE")
def manage_standalone_subnet6_options(subnet: str) -> Union[str, Response, Tuple[str, int]]:
    """Options for subnet6s that live directly under Dhcp6 (not in a shared-network)."""
    config = load_json(current_app.config["DHCP6_CONFIG_FILE"])

    target_subnet, found_network_name = _find_subnet6(config, subnet)
    if not target_subnet or found_network_name is not None:
        return "Subnet not found", 404

    if request.method == "POST":
        option_name = request.form.get("option-name")
        option_data = request.form.get("option-data")
        if option_name and option_data:
            if not validate_option_data(option_name) or not validate_option_data(option_data):
                flash("Option name/data contains control characters or angle brackets, which are not allowed.", "danger")
                return redirect(url_for("main.options.manage_standalone_subnet6_options", subnet=subnet))

            opts = target_subnet.setdefault("option-data", [])
            for opt in opts:
                if opt.get("name") == option_name:
                    opt["data"] = option_data
                    break
            else:
                opts.append({"name": option_name, "data": option_data})
            save_kea_config(config, current_app.config["DHCP6_CONFIG_FILE"], current_app.config["BACKUP_DIR"])
        return redirect(url_for("main.options.manage_standalone_subnet6_options", subnet=subnet))

    options = target_subnet.get("option-data", [])
    return render_template("manage_options.html",
                           shared_network_name="(standalone)",
                           subnet=subnet,
                           options=options,
                           version="6",
                           standalone=True)


@options_bp.route("/options/subnet6/standalone/<path:subnet>/delete", methods=["POST"])
@login_required
@with_config_lock("DHCP6_CONFIG_FILE")
def delete_standalone_subnet6_option(subnet: str) -> Response:
    """Delete a DHCPv6 option from a standalone subnet."""
    option_name = request.form.get("option-name")
    config = load_json(current_app.config["DHCP6_CONFIG_FILE"])

    target_subnet, found_network_name = _find_subnet6(config, subnet)
    if target_subnet and found_network_name is None and "option-data" in target_subnet:
        target_subnet["option-data"] = [o for o in target_subnet["option-data"] if o.get("name") != option_name]

    save_kea_config(config, current_app.config["DHCP6_CONFIG_FILE"], current_app.config["BACKUP_DIR"])
    return redirect(url_for("main.options.manage_standalone_subnet6_options", subnet=subnet))