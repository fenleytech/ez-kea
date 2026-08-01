# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

from typing import Any, Dict, Optional, Union, Tuple
from flask_login import login_required
from flask import Blueprint, render_template, request, redirect, url_for, current_app
from werkzeug.wrappers import Response
from ..core.config_manager import load_json, save_kea_config, with_config_lock
from ..core.validation import classify_network_address, validate_mac_address, validate_ip_range, validate_duid, has_overlap, return_available_ips, get_active_leases, get_active_leases6, unix_to_human_readable, sanitize_hostname
import ipaddress

dhcp6_bp = Blueprint('dhcp6', __name__)


def _find_subnet6(config: Dict[str, Any], subnet: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Locate a subnet6 object by its subnet string.
    Searches standalone subnets (Dhcp6.subnet6[]) first, then subnets
    nested inside shared-networks.
    Returns (subnet_obj, shared_network_name); shared_network_name is None
    when the match is a standalone subnet. Returns (None, None) if no
    subnet with that address exists anywhere in the config.
    """
    dhcp6 = config.get("Dhcp6", {})
    for subnet_obj in dhcp6.get("subnet6", []):
        if subnet_obj.get("subnet") == subnet:
            return subnet_obj, None
    for shared_network in dhcp6.get("shared-networks", []):
        for subnet_obj in shared_network.get("subnet6", []):
            if subnet_obj.get("subnet") == subnet:
                return subnet_obj, shared_network.get("name")
    return None, None


def _next_subnet6_id(config: Dict[str, Any]) -> int:
    """Return the next available subnet6 ID. Kea keeps v4/v6 subnet-id
    spaces separate, so this only scans Dhcp6 — it must not be merged with
    dhcp4.py's _next_subnet_id()."""
    used = set()
    dhcp6 = config.get("Dhcp6", {})
    for s in dhcp6.get("subnet6", []):
        used.add(s.get("id", 0))
    for net in dhcp6.get("shared-networks", []):
        for s in net.get("subnet6", []):
            used.add(s.get("id", 0))
    return max(used, default=0) + 1


@dhcp6_bp.route("/pools6")
@login_required
def pools6() -> str:
    """Render the main DHCPv6 pools configuration view."""
    config = load_json(current_app.config["DHCP6_CONFIG_FILE"])
    dhcp6 = config.get("Dhcp6", {})
    shared_networks = dhcp6.get("shared-networks", [])
    # Top-level Dhcp6.subnet6[] -- subnets not inside any shared network. Kea
    # writes these for a plain single-subnet setup (ISC's own example config
    # does), so omitting them here rendered a perfectly normal server as
    # "No IPv6 Shared Networks Configured" and hid live subnets completely.
    standalone_subnets = dhcp6.get("subnet6", [])
    return render_template(
        "pools6.html",
        shared_networks=shared_networks,
        standalone_subnets=standalone_subnets,
    )

@dhcp6_bp.route("/new-shared-network6", methods=["GET", "POST"])
@login_required
@with_config_lock("DHCP6_CONFIG_FILE")
def new_shared_network6() -> Union[str, Response]:
    """Create a new DHCPv6 shared network and save it to the config."""
    errors = []
    if request.method == "POST":
        shared_network_name = request.form.get("shared-network-name")
        if not shared_network_name:
            errors.append("Shared network name is required.")
        else:
            config_file = current_app.config["DHCP6_CONFIG_FILE"]
            config = load_json(config_file)
            if "Dhcp6" not in config: config["Dhcp6"] = {"shared-networks": []}
            if "shared-networks" not in config["Dhcp6"]: config["Dhcp6"]["shared-networks"] = []
            
            # Check if name exists
            for net in config["Dhcp6"]["shared-networks"]:
                if net.get("name") == shared_network_name:
                    errors.append(f"Shared network '{shared_network_name}' already exists.")
                    break
            
            if not errors:
                config["Dhcp6"]["shared-networks"].append({"name": shared_network_name, "subnet6": []})
                save_kea_config(config, config_file, current_app.config["BACKUP_DIR"])
                return redirect(url_for('main.dhcp6.pools6'))
                
    return render_template("new_shared_network6.html", errors=errors)

@dhcp6_bp.route("/delete-shared-network6", methods=["POST"])
@login_required
@with_config_lock("DHCP6_CONFIG_FILE")
def delete_shared_network6() -> Response:
    """Remove a specified shared network from the DHCPv6 configuration."""
    shared_network_name = request.form.get("shared-network-name")
    config_file = current_app.config["DHCP6_CONFIG_FILE"]
    config = load_json(config_file)
    
    if "Dhcp6" in config and "shared-networks" in config["Dhcp6"]:
        config["Dhcp6"]["shared-networks"] = [
            net for net in config["Dhcp6"]["shared-networks"] if net.get("name") != shared_network_name
        ]
        save_kea_config(config, config_file, current_app.config["BACKUP_DIR"])
        
    return redirect(url_for('main.dhcp6.pools6'))

@dhcp6_bp.route("/new-subnet6", methods=["GET", "POST"])
@login_required
@with_config_lock("DHCP6_CONFIG_FILE")
def new_subnet6() -> Union[str, Response, Tuple[str, int]]:
    """Create a new DHCPv6 subnet entry, validating its address and prefix delegation."""
    errors = []
    if request.method == "GET":
        shared_network_name = request.args.get("shared_network_name", "")
        return render_template("new_subnet6.html", shared_network_name=shared_network_name, errors=errors)
        
    elif request.method == "POST":
        subnet = request.form.get("subnet")
        shared_network_name = request.form.get("shared-network-name", "").strip()
        pd_pool = request.form.get("pd-pool") # Prefix Delegation Pool (e.g. 2001:db8:1::/64)
        pd_length = request.form.get("pd-length") # Delegated length (e.g. 64)
        pool_start = request.form.get("pool-start") # Standard IA_NA address pool start
        pool_end = request.form.get("pool-end") # Standard IA_NA address pool end

        config_file = current_app.config["DHCP6_CONFIG_FILE"]
        config = load_json(config_file)

        if not subnet:
            errors.append("Subnet is required.")
        else:
            try:
                ipaddress.IPv6Network(subnet)
            except ValueError:
                errors.append("Invalid IPv6 subnet format. Please enter a valid network address (e.g., 2001:db8::/64).")

        # A blank shared-network-name is legitimate: it means a standalone
        # subnet under Dhcp6.subnet6[], which is how Kea writes a plain
        # single-subnet server. Requiring a group here was what forced every
        # v6 subnet into a shared network and left standalone ones
        # unrepresentable from the UI.

        if not errors:
            overlap = has_overlap(subnet, config, "Dhcp6")
            if overlap:
                errors.append(f"New subnet entry overlaps with existing configured subnet: {overlap}")

        pd_length_int = None
        if pd_pool:
            try:
                pd_pool_network = ipaddress.IPv6Network(pd_pool)
            except ValueError:
                pd_pool_network = None
                errors.append("Invalid Prefix Delegation Pool format.")

            if not pd_length:
                errors.append("Prefix Delegation Length is required when specifying a PD Pool.")
            else:
                try:
                    pd_length_int = int(pd_length)
                except ValueError:
                    pd_length_int = None
                    errors.append("Prefix Delegation Length must be a whole number.")

                if pd_length_int is not None:
                    if not (1 <= pd_length_int <= 128):
                        errors.append("Prefix Delegation Length must be between 1 and 128.")
                    elif pd_pool_network is not None and pd_length_int < pd_pool_network.prefixlen:
                        errors.append(
                            f"Delegated length (/{pd_length_int}) must be greater than or equal to "
                            f"the PD pool's own prefix length (/{pd_pool_network.prefixlen})."
                        )

        # Standard stateful address assignment (IA_NA) — a normal range of
        # individual addresses for end hosts, distinct from (and coexisting
        # with) the PD pool above which delegates whole prefixes to routers.
        if pool_start or pool_end:
            if not pool_start or not pool_end:
                errors.append("Both Pool Start and Pool End are required for a standard address pool.")
            elif not subnet:
                pass  # Already reported "Subnet is required." above.
            elif not validate_ip_range(subnet, pool_start, pool_end):
                errors.append(
                    "Invalid IPv6 address pool range. Please ensure the range is within the "
                    "subnet and start address < end address."
                )

        if errors:
            return render_template("new_subnet6.html", shared_network_name=shared_network_name, errors=errors), 400

        new_subnet_obj = {
            "id": _next_subnet6_id(config),
            "subnet": subnet,
            "reservations": []
        }

        if pool_start and pool_end:
            new_subnet_obj["pools"] = [{"pool": f"{pool_start} - {pool_end}"}]

        if pd_pool:
            new_subnet_obj["pd-pools"] = [{"prefix": pd_pool, "delegated-len": pd_length_int}]

        dhcp6 = config.setdefault("Dhcp6", {})
        if not shared_network_name:
            # No group named: a standalone subnet under Dhcp6.subnet6[], same
            # as the v4 path. Previously this fell through to the branch below
            # and created a shared network literally named "", which is not
            # something anyone asked for.
            dhcp6.setdefault("subnet6", []).append(new_subnet_obj)
        else:
            # Match an existing shared network by name, or auto-create one if it
            # doesn't exist yet — mirrors the v4 behavior in new_subnet(), so a
            # shared-network-name that doesn't match anything no longer silently
            # drops the subnet.
            networks = dhcp6.setdefault("shared-networks", [])
            for shared_network in networks:
                if shared_network.get("name") == shared_network_name:
                    shared_network.setdefault("subnet6", []).append(new_subnet_obj)
                    break
            else:
                networks.append({"name": shared_network_name, "subnet6": [new_subnet_obj]})

        save_kea_config(config, config_file, current_app.config["BACKUP_DIR"])
        return redirect(url_for("main.dhcp6.pools6"))

@dhcp6_bp.route("/delete-subnet6", methods=["POST"])
@login_required
@with_config_lock("DHCP6_CONFIG_FILE")
def delete_subnet6() -> Response:
    """Delete a specific subnet from a shared network in DHCPv6."""
    shared_network_name = request.form.get("shared-network-name")
    subnet = request.form.get("subnet")
    config_file = current_app.config["DHCP6_CONFIG_FILE"]
    config = load_json(config_file)

    if not shared_network_name:
        # Standalone subnet (Dhcp6.subnet6[]). Without this the delete button on
        # a standalone subnet silently did nothing: the loop below only ever
        # searched inside shared networks.
        dhcp6 = config.get("Dhcp6", {})
        if "subnet6" in dhcp6:
            dhcp6["subnet6"] = [sub for sub in dhcp6["subnet6"] if sub.get("subnet") != subnet]
    else:
        for network in config.get("Dhcp6", {}).get("shared-networks", []):
            if network.get("name") == shared_network_name:
                if "subnet6" in network:
                    network["subnet6"] = [sub for sub in network["subnet6"] if sub.get("subnet") != subnet]
                break

    save_kea_config(config, config_file, current_app.config["BACKUP_DIR"])
    return redirect(url_for("main.dhcp6.pools6"))


# ── DUID-based reservations ──────────────────────────────────────────────────
# Kea DHCPv6 reservations are keyed by DUID rather than MAC, and use plural
# ip-addresses/prefixes arrays rather than v4's singular ip-address — a
# reservation can carry an address, a delegated prefix, or (per Kea) both.

def _duid_reservation_sort_key(reservation: Dict[str, Any]) -> Tuple[int, Any]:
    """Sort key for reservation listing. Valid IPv6 addresses sort
    numerically first; prefix-only (or otherwise addressless) reservations
    sort after, by DUID, instead of crashing the whole page."""
    ip_addresses = reservation.get("ip-addresses") or []
    if ip_addresses:
        try:
            return (0, int(ipaddress.IPv6Address(ip_addresses[0])))
        except (ValueError, TypeError):
            pass
    return (1, reservation.get("duid", ""))

def _collect_subnet6_cidrs(config: Dict[str, Any]) -> list:
    """All configured subnet6 CIDRs (standalone + shared-network-nested), for
    populating the reservation form's subnet picker."""
    dhcp6 = config.get("Dhcp6", {})
    subnets = [s.get("subnet") for s in dhcp6.get("subnet6", [])]
    for network in dhcp6.get("shared-networks", []):
        subnets.extend(s.get("subnet") for s in network.get("subnet6", []))
    return subnets

@dhcp6_bp.route("/reservations6")
@login_required
def reservations6() -> str:
    """Render the list of DUID-based reservations across all configured subnet6s."""
    config = load_json(current_app.config["DHCP6_CONFIG_FILE"])
    reservations = []

    # Standalone subnets (Dhcp6.subnet6[])
    for subnet in config.get("Dhcp6", {}).get("subnet6", []):
        for reservation in subnet.get("reservations", []):
            res_copy = reservation.copy()
            res_copy["shared_network_name"] = None
            res_copy["subnet"] = subnet.get("subnet")
            res_copy["hostname"] = res_copy.get("hostname", "N/A")
            reservations.append(res_copy)

    # Subnets nested inside shared-networks
    for network in config.get("Dhcp6", {}).get("shared-networks", []):
        shared_network_name = network.get("name")
        for subnet in network.get("subnet6", []):
            for reservation in subnet.get("reservations", []):
                res_copy = reservation.copy()
                res_copy["shared_network_name"] = shared_network_name
                res_copy["subnet"] = subnet.get("subnet")
                res_copy["hostname"] = res_copy.get("hostname", "N/A")
                reservations.append(res_copy)

    reservations.sort(key=_duid_reservation_sort_key)
    return render_template("duid_reservations.html", reservations=reservations)

@dhcp6_bp.route("/new-reservation6", methods=["GET", "POST"])
@login_required
@with_config_lock("DHCP6_CONFIG_FILE")
def new_reservation6() -> Union[str, Response, Tuple[str, int]]:
    """Add a new DUID-based reservation for a specific IPv6 address and/or delegated prefix."""
    config = load_json(current_app.config["DHCP6_CONFIG_FILE"])
    # A free-text subnet field backed by a picker of existing subnets — not a
    # pre-computed available-IP dropdown like v4's return_available_ips();
    # enumerating a /64's host space isn't feasible.
    available_subnets = _collect_subnet6_cidrs(config)
    errors = []

    if request.method == "POST":
        subnet = request.form.get("subnet")
        duid = request.form.get("duid")
        hostname_raw = request.form.get("hostname")
        ip_address = request.form.get("ip-address", "").strip()
        prefix = request.form.get("prefix", "").strip()

        if not subnet: errors.append("Subnet is required.")

        if not duid: errors.append("DUID is required.")
        elif not validate_duid(duid): errors.append("Invalid DUID format.")

        hostname = sanitize_hostname(hostname_raw) if hostname_raw else ""
        if not hostname: errors.append("Hostname is required.")

        if not ip_address and not prefix:
            errors.append("Either an IPv6 address or a delegated prefix is required.")
        if ip_address:
            try:
                ipaddress.IPv6Address(ip_address)
            except ValueError:
                errors.append("Invalid IPv6 address format.")
        if prefix:
            try:
                ipaddress.IPv6Network(prefix)
            except ValueError:
                errors.append("Invalid IPv6 prefix format.")

        subnet_obj = None
        if subnet:
            subnet_obj, _ = _find_subnet6(config, subnet)
            if subnet_obj is None:
                errors.append(f"Subnet '{subnet}' was not found in the configuration.")

        if errors:
            return render_template("new_reservation6.html", available_subnets=available_subnets, errors=errors), 400

        new_reservation = {"duid": duid, "hostname": hostname}
        if ip_address:
            new_reservation["ip-addresses"] = [ip_address]
        if prefix:
            new_reservation["prefixes"] = [prefix]

        subnet_obj.setdefault("reservations", []).append(new_reservation)

        save_kea_config(config, current_app.config["DHCP6_CONFIG_FILE"], current_app.config["BACKUP_DIR"])
        return redirect(url_for("main.dhcp6.reservations6"))

    return render_template("new_reservation6.html", available_subnets=available_subnets, errors=errors)

@dhcp6_bp.route("/delete-reservation6", methods=["POST"])
@login_required
@with_config_lock("DHCP6_CONFIG_FILE")
def delete_reservation6() -> Response:
    """Delete a DUID-based reservation, from either a standalone subnet or
    one nested inside a shared network."""
    duid = request.form.get("duid")
    subnet = request.form.get("subnet")
    config = load_json(current_app.config["DHCP6_CONFIG_FILE"])

    if subnet:
        subnet_obj, _ = _find_subnet6(config, subnet)
        if subnet_obj and "reservations" in subnet_obj:
            subnet_obj["reservations"] = [
                res for res in subnet_obj["reservations"] if res.get("duid") != duid
            ]

    save_kea_config(config, current_app.config["DHCP6_CONFIG_FILE"], current_app.config["BACKUP_DIR"])
    return redirect(url_for("main.dhcp6.reservations6"))

@dhcp6_bp.route("/leases6")
@login_required
def leases6() -> str:
    """Render the active DHCPv6 leases table (IA_NA/IA_TA/IA_PD) from the keystore."""
    active_leases = get_active_leases6(current_app.config["DHCP6_LEASES_FILE"])

    for lease in active_leases:
        lease["expiration_time"] = unix_to_human_readable(lease["expire"])

    return render_template("leases6.html", leases=active_leases)