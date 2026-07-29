from typing import Any, Dict, Optional, Union, Tuple
from flask_login import login_required
from flask import Blueprint, render_template, request, redirect, url_for, current_app
from werkzeug.wrappers import Response
from ..core.config_manager import load_json, save_json, with_config_lock
from ..core.validation import classify_network_address, validate_mac_address, validate_ip_range, validate_ipv4_address, has_overlap, return_available_ips, get_active_leases, sanitize_hostname
from ..license import license_gate

dhcp4_bp = Blueprint('dhcp4', __name__)


def _find_subnet4(config: Dict[str, Any], subnet: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Locate a subnet4 object by its subnet string.
    Searches standalone subnets (Dhcp4.subnet4[]) first, then subnets
    nested inside shared-networks.
    Returns (subnet_obj, shared_network_name); shared_network_name is None
    when the match is a standalone subnet. Returns (None, None) if no
    subnet with that address exists anywhere in the config.
    """
    dhcp4 = config.get("Dhcp4", {})
    for subnet_obj in dhcp4.get("subnet4", []):
        if subnet_obj.get("subnet") == subnet:
            return subnet_obj, None
    for shared_network in dhcp4.get("shared-networks", []):
        for subnet_obj in shared_network.get("subnet4", []):
            if subnet_obj.get("subnet") == subnet:
                return subnet_obj, shared_network.get("name")
    return None, None

@dhcp4_bp.route("/pools")
@login_required
def pools() -> str:
    """Render the main DHCPv4 pools configuration page."""
    config = load_json(current_app.config["DHCP_CONFIG_FILE"])
    shared_networks = config.get("Dhcp4", {}).get("shared-networks", [])
    standalone_subnets = config.get("Dhcp4", {}).get("subnet4", [])
    return render_template("pools.html", shared_networks=shared_networks, standalone_subnets=standalone_subnets)

@dhcp4_bp.route("/new-shared-network", methods=["GET", "POST"])
@login_required
@license_gate
@with_config_lock()
def new_shared_network() -> Union[str, Response]:
    """Create a new DHCPv4 shared network and save it to the configuration."""
    errors = []
    if request.method == "POST":
        shared_network_name = request.form.get("shared-network-name")
        if not shared_network_name:
            errors.append("Shared network name is required.")
        else:
            config = load_json(current_app.config["DHCP_CONFIG_FILE"])
            if "Dhcp4" not in config: config["Dhcp4"] = {"shared-networks": []}
            if "shared-networks" not in config["Dhcp4"]: config["Dhcp4"]["shared-networks"] = []
            
            # Check if name exists
            for net in config["Dhcp4"]["shared-networks"]:
                if net.get("name") == shared_network_name:
                    errors.append(f"Shared network '{shared_network_name}' already exists.")
                    break
            
            if not errors:
                config["Dhcp4"]["shared-networks"].append({"name": shared_network_name, "subnet4": []})
                save_json(config, current_app.config["DHCP_CONFIG_FILE"])
                return redirect(url_for('main.dhcp4.pools'))
                
    return render_template("new_shared_network.html", errors=errors)

@dhcp4_bp.route("/delete-shared-network", methods=["POST"])
@login_required
@license_gate
@with_config_lock()
def delete_shared_network() -> Response:
    """Remove a specified shared network from the DHCPv4 configuration."""
    shared_network_name = request.form.get("shared-network-name")
    config = load_json(current_app.config["DHCP_CONFIG_FILE"])
    
    if "Dhcp4" in config and "shared-networks" in config["Dhcp4"]:
        config["Dhcp4"]["shared-networks"] = [
            net for net in config["Dhcp4"]["shared-networks"] if net.get("name") != shared_network_name
        ]
        save_json(config, current_app.config["DHCP_CONFIG_FILE"])
        
    return redirect(url_for('main.dhcp4.pools'))

@dhcp4_bp.route("/new-subnet", methods=["GET", "POST"])
@login_required
@license_gate
@with_config_lock()
def new_subnet() -> Union[str, Response, Tuple[str, int]]:
    """Create a new subnet entry, validating its address and overlapping range."""
    errors = []
    if request.method == "GET":
        shared_network_name = request.args.get("shared_network_name", "")
        return render_template("new_subnet.html", shared_network_name=shared_network_name, errors=errors)
        
    elif request.method == "POST":
        subnet = request.form.get("subnet")
        routers = request.form.get("routers")
        static_only = request.form.get("static-only") == "on"
        shared_network_name = request.form.get("shared-network-name", "").strip()
        
        config = load_json(current_app.config["DHCP_CONFIG_FILE"])

        if not subnet:
            errors.append("Subnet is required.")
        elif classify_network_address(subnet) != 2:
            errors.append("Invalid subnet format. Please enter a valid network address (e.g., 192.168.1.0/24).")
            
        if not errors:
            overlap = has_overlap(subnet, config, "Dhcp4")
            if overlap:
                errors.append(f"New subnet entry overlaps with existing configured subnet: {overlap}")

        if not routers:
            errors.append("Router Address is required.")
        elif classify_network_address(routers) != 2:
            errors.append("Router address must be a single IP (e.g., 192.168.1.1).")

        range_start, range_end = None, None
        if not static_only:
            range_start = request.form.get("range-start")
            range_end = request.form.get("range-end")
            if not range_start or classify_network_address(range_start) != 2:
                errors.append("Range start is missing or incorrect.")
            if not range_end or classify_network_address(range_end) != 2:
                errors.append("Range end is missing or incorrect.")
            if range_start and range_end and subnet and not validate_ip_range(subnet, range_start, range_end):
                errors.append("Invalid IP range. Please ensure the range is within the subnet and start_ip < end_ip.")

        if errors:
            return render_template("new_subnet.html", shared_network_name=shared_network_name, errors=errors), 400

        new_subnet_obj = {
            "id": _next_subnet_id(config),
            "subnet": subnet,
            "option-data": [{"name": "routers", "data": routers}] if routers else [],
            "reservations": []
        }
        if not static_only:
            new_subnet_obj["pools"] = [{"pool": f"{range_start} - {range_end}"}]

        if shared_network_name:
            # Add to named shared-network
            dhcp4 = config.setdefault("Dhcp4", {})
            networks = dhcp4.setdefault("shared-networks", [])
            for net in networks:
                if net.get("name") == shared_network_name:
                    net.setdefault("subnet4", []).append(new_subnet_obj)
                    break
            else:
                # Create the shared-network if it doesn't exist
                networks.append({"name": shared_network_name, "subnet4": [new_subnet_obj]})
        else:
            # Add as standalone subnet directly under Dhcp4
            config.setdefault("Dhcp4", {}).setdefault("subnet4", []).append(new_subnet_obj)

        save_json(config, current_app.config["DHCP_CONFIG_FILE"])
        return redirect(url_for("main.dhcp4.pools"))

@dhcp4_bp.route("/delete-subnet", methods=["POST"])
@login_required
@license_gate
@with_config_lock()
def delete_subnet() -> Response:
    """Delete a specific subnet from a shared network or standalone list."""
    shared_network_name = request.form.get("shared-network-name", "").strip()
    subnet = request.form.get("subnet")
    config = load_json(current_app.config["DHCP_CONFIG_FILE"])

    if shared_network_name:
        for network in config.get("Dhcp4", {}).get("shared-networks", []):
            if network.get("name") == shared_network_name:
                if "subnet4" in network:
                    network["subnet4"] = [s for s in network["subnet4"] if s.get("subnet") != subnet]
                break
    else:
        dhcp4 = config.get("Dhcp4", {})
        dhcp4["subnet4"] = [s for s in dhcp4.get("subnet4", []) if s.get("subnet") != subnet]

    save_json(config, current_app.config["DHCP_CONFIG_FILE"])
    return redirect(url_for("main.dhcp4.pools"))


def _next_subnet_id(config: Dict[str, Any]) -> int:
    """Return the next available subnet ID across all subnets."""
    used = set()
    dhcp4 = config.get("Dhcp4", {})
    for s in dhcp4.get("subnet4", []):
        used.add(s.get("id", 0))
    for net in dhcp4.get("shared-networks", []):
        for s in net.get("subnet4", []):
            used.add(s.get("id", 0))
    return max(used, default=0) + 1

def _mac_reservation_sort_key(reservation: Dict[str, Any]) -> Tuple[int, Any]:
    """Sort key for reservation listing. Valid IPv4 addresses sort
    numerically first; anything unparseable (a bad value already saved in
    someone's config) sorts last instead of crashing the whole page."""
    ip_address = reservation.get("ip-address", "0.0.0.0")
    try:
        return (0, [int(p) for p in ip_address.split(".")])
    except (ValueError, AttributeError, TypeError):
        return (1, ip_address)

@dhcp4_bp.route("/mac-reservations")
@login_required
def mac_reservations() -> str:
    """Render the list of MAC address reservations across all configured subnets."""
    config = load_json(current_app.config["DHCP_CONFIG_FILE"])
    mac_reservations = []

    # Standalone subnets (Dhcp4.subnet4[])
    for subnet in config.get("Dhcp4", {}).get("subnet4", []):
        for reservation in subnet.get("reservations", []):
            res_copy = reservation.copy()
            res_copy["shared_network_name"] = None
            res_copy["subnet"] = subnet.get("subnet")
            res_copy["hostname"] = res_copy.get("hostname", "N/A")
            mac_reservations.append(res_copy)

    # Subnets nested inside shared-networks
    for network in config.get("Dhcp4", {}).get("shared-networks", []):
        shared_network_name = network.get("name")
        for subnet in network.get("subnet4", []):
            for reservation in subnet.get("reservations", []):
                res_copy = reservation.copy()
                res_copy["shared_network_name"] = shared_network_name
                res_copy["subnet"] = subnet.get("subnet")
                res_copy["hostname"] = res_copy.get("hostname", "N/A")
                mac_reservations.append(res_copy)

    mac_reservations.sort(key=_mac_reservation_sort_key)
    return render_template("mac_reservations.html", mac_reservations=mac_reservations)

@dhcp4_bp.route("/new-reservation", methods=["GET", "POST"])
@login_required
@license_gate
@with_config_lock()
def new_reservation() -> Union[str, Response, Tuple[str, int]]:
    """Add a new static DHCP reservation for a specific MAC address."""
    config = load_json(current_app.config["DHCP_CONFIG_FILE"])
    subnet_data = return_available_ips(config, current_app.config["DHCP_LEASES_FILE"])
    errors = []

    if request.method == "POST":
        subnet = request.form.get("subnet")
        ip_address = request.form.get("ip-address")
        hostname_raw = request.form.get("hostname")
        mac_address = request.form.get("mac-address")

        if not subnet: errors.append("Subnet is required.")
        if not ip_address: errors.append("IP address is required.")
        elif not validate_ipv4_address(ip_address): errors.append("Invalid IPv4 address format for IP address.")

        # Sanitize before checking "required" — an all-emoji (or otherwise
        # fully-stripped) hostname must not sneak past this check as if it
        # were a valid, non-empty value.
        hostname = sanitize_hostname(hostname_raw) if hostname_raw else ""
        if not hostname: errors.append("Hostname is required.")

        if not mac_address: errors.append("MAC is required.")
        elif not validate_mac_address(mac_address): errors.append("Invalid MAC Address format.")

        subnet_obj = None
        if subnet:
            subnet_obj, _ = _find_subnet4(config, subnet)
            if subnet_obj is None:
                errors.append(f"Subnet '{subnet}' was not found in the configuration.")

        if errors:
            return render_template("new_reservation.html", subnet_data=subnet_data, errors=errors), 400

        subnet_obj.setdefault("reservations", []).append({
            "hostname": hostname,
            "hw-address": mac_address,
            "ip-address": ip_address
        })

        save_json(config, current_app.config["DHCP_CONFIG_FILE"])
        return redirect(url_for("main.dhcp4.mac_reservations"))

    return render_template("new_reservation.html", subnet_data=subnet_data, errors=errors)

@dhcp4_bp.route("/delete-reservation", methods=["POST"])
@login_required
@license_gate
@with_config_lock()
def delete_reservation() -> Response:
    """Delete a static MAC-based IP reservation, from either a standalone
    subnet or one nested inside a shared network."""
    hw_address = request.form.get("hw-address")
    subnet = request.form.get("subnet")
    shared_network_name = request.form.get("shared-network-name", "").strip()
    config = load_json(current_app.config["DHCP_CONFIG_FILE"])

    if subnet:
        # Preferred path: identify the exact subnet (standalone or shared)
        # the reservation lives on.
        subnet_obj, _ = _find_subnet4(config, subnet)
        if subnet_obj and "reservations" in subnet_obj:
            subnet_obj["reservations"] = [
                res for res in subnet_obj["reservations"] if res.get("hw-address") != hw_address
            ]
    elif shared_network_name:
        # Legacy fallback for callers that only supply a shared-network name.
        for network in config.get("Dhcp4", {}).get("shared-networks", []):
            if network.get("name") == shared_network_name:
                for subnet_obj in network.get("subnet4", []):
                    if "reservations" in subnet_obj:
                        subnet_obj["reservations"] = [
                            res for res in subnet_obj["reservations"] if res.get("hw-address") != hw_address
                        ]
                break

    save_json(config, current_app.config["DHCP_CONFIG_FILE"])
    return redirect(url_for("main.dhcp4.mac_reservations"))

@dhcp4_bp.route("/leases")
@login_required
def leases() -> str:
    """Render the active DHCP leases table from the keystore."""
    from ..core.validation import unix_to_human_readable, get_active_leases
    active_leases = get_active_leases(current_app.config["DHCP_LEASES_FILE"])
    
    # Format dates
    for lease in active_leases:
         lease["expiration_time"] = unix_to_human_readable(lease["expire"])
         
    return render_template("leases.html", leases=active_leases)