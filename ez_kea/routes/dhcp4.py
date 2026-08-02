# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

from typing import Any, Dict, Optional, Union, Tuple
from flask_login import login_required
from flask import Blueprint, render_template, request, redirect, url_for, current_app, flash
from werkzeug.wrappers import Response
from ..core.config_manager import load_json, save_kea_config, with_config_lock
from ..core.validation import classify_network_address, validate_mac_address, validate_ip_range, validate_ipv4_address, has_overlap, return_available_ips, get_active_leases, sanitize_hostname
from ..core import state_index
from ..core.csv_export import stream_csv_response

dhcp4_bp = Blueprint('dhcp4', __name__)


def _pagination_params() -> Tuple[int, str, str]:
    """Page number, sort column, and direction, off the request -- the same
    three params every search-index-backed list page reads."""
    try:
        page = max(1, int(request.values.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    sort = (request.values.get("sort", "") or "").strip()
    direction = (request.values.get("direction", "") or "").strip().lower()
    return page, sort, direction


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
                save_kea_config(config, current_app.config["DHCP_CONFIG_FILE"], current_app.config["BACKUP_DIR"])
                return redirect(url_for('main.dhcp4.pools'))
                
    return render_template("new_shared_network.html", errors=errors)

@dhcp4_bp.route("/delete-shared-network", methods=["POST"])
@login_required
@with_config_lock()
def delete_shared_network() -> Response:
    """Remove a specified shared network from the DHCPv4 configuration."""
    shared_network_name = request.form.get("shared-network-name")
    config = load_json(current_app.config["DHCP_CONFIG_FILE"])
    
    if "Dhcp4" in config and "shared-networks" in config["Dhcp4"]:
        config["Dhcp4"]["shared-networks"] = [
            net for net in config["Dhcp4"]["shared-networks"] if net.get("name") != shared_network_name
        ]
        save_kea_config(config, current_app.config["DHCP_CONFIG_FILE"], current_app.config["BACKUP_DIR"])
        
    return redirect(url_for('main.dhcp4.pools'))

@dhcp4_bp.route("/edit-shared-network", methods=["GET", "POST"])
@login_required
@with_config_lock()
def edit_shared_network() -> Union[str, Response, Tuple[str, int]]:
    """Rename an existing DHCPv4 shared network in place."""
    config = load_json(current_app.config["DHCP_CONFIG_FILE"])
    errors = []

    if request.method == "GET":
        shared_network_name = request.args.get("shared-network-name")
        network = next((net for net in config.get("Dhcp4", {}).get("shared-networks", [])
                         if net.get("name") == shared_network_name), None)
        if network is None:
            flash("Shared network not found.", "danger")
            return redirect(url_for("main.dhcp4.pools"))
        return render_template("new_shared_network.html", errors=errors, editing=True, original_name=shared_network_name)

    original_name = request.form.get("original-shared-network-name")
    shared_network_name = request.form.get("shared-network-name")
    networks = config.get("Dhcp4", {}).get("shared-networks", [])
    network = next((net for net in networks if net.get("name") == original_name), None)

    if not shared_network_name:
        errors.append("Shared network name is required.")
    elif network is None:
        errors.append("Shared network was not found in the configuration.")
    else:
        for net in networks:
            if net is not network and net.get("name") == shared_network_name:
                errors.append(f"Shared network '{shared_network_name}' already exists.")
                break

    if errors:
        return render_template("new_shared_network.html", errors=errors, editing=True, original_name=original_name), 400

    network["name"] = shared_network_name
    save_kea_config(config, current_app.config["DHCP_CONFIG_FILE"], current_app.config["BACKUP_DIR"])
    return redirect(url_for('main.dhcp4.pools'))

@dhcp4_bp.route("/new-subnet", methods=["GET", "POST"])
@login_required
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

        save_kea_config(config, current_app.config["DHCP_CONFIG_FILE"], current_app.config["BACKUP_DIR"])
        return redirect(url_for("main.dhcp4.pools"))

@dhcp4_bp.route("/delete-subnet", methods=["POST"])
@login_required
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

    save_kea_config(config, current_app.config["DHCP_CONFIG_FILE"], current_app.config["BACKUP_DIR"])
    return redirect(url_for("main.dhcp4.pools"))

@dhcp4_bp.route("/edit-subnet", methods=["GET", "POST"])
@login_required
@with_config_lock()
def edit_subnet() -> Union[str, Response, Tuple[str, int]]:
    """Edit an existing subnet's gateway, dynamic pool, and static-only
    setting in place. The subnet's CIDR is locked -- migrating an
    already-populated subnet to a new address range is a materially
    different, riskier operation than fixing its gateway or pool."""
    config = load_json(current_app.config["DHCP_CONFIG_FILE"])
    errors = []

    if request.method == "GET":
        subnet = request.args.get("subnet")
        subnet_obj, shared_network_name = _find_subnet4(config, subnet)
        if subnet_obj is None:
            flash("Subnet not found.", "danger")
            return redirect(url_for("main.dhcp4.pools"))

        current_router = None
        for option in subnet_obj.get("option-data", []):
            if option.get("name") == "routers":
                current_router = option.get("data")
                break

        static_only = "pools" not in subnet_obj
        range_start, range_end = "", ""
        if subnet_obj.get("pools"):
            pool_str = subnet_obj["pools"][0].get("pool", "")
            if " - " in pool_str:
                range_start, range_end = pool_str.split(" - ", 1)

        return render_template(
            "new_subnet.html", shared_network_name=shared_network_name or "", errors=errors,
            editing=True, subnet=subnet, current_router=current_router,
            static_only=static_only, range_start=range_start, range_end=range_end,
        )

    # POST
    subnet = request.form.get("subnet")
    routers = request.form.get("routers")
    static_only = request.form.get("static-only") == "on"
    shared_network_name = request.form.get("shared-network-name", "").strip()

    subnet_obj, _ = _find_subnet4(config, subnet)
    if subnet_obj is None:
        errors.append(f"Subnet '{subnet}' was not found in the configuration.")

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
        return render_template(
            "new_subnet.html", shared_network_name=shared_network_name, errors=errors,
            editing=True, subnet=subnet, current_router=routers,
            static_only=static_only, range_start=range_start or "", range_end=range_end or "",
        ), 400

    subnet_obj["option-data"] = [{"name": "routers", "data": routers}] if routers else []
    if static_only:
        subnet_obj.pop("pools", None)
    else:
        subnet_obj["pools"] = [{"pool": f"{range_start} - {range_end}"}]

    save_kea_config(config, current_app.config["DHCP_CONFIG_FILE"], current_app.config["BACKUP_DIR"])
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

def _find_reservation4(config: Dict[str, Any], hw_address: str, subnet: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Locate a MAC reservation by hw-address within a specific subnet.
    Returns (subnet_obj, reservation_obj); either is None if the subnet
    itself, or the reservation within it, can't be found."""
    subnet_obj, _ = _find_subnet4(config, subnet)
    if subnet_obj is None:
        return None, None
    for reservation in subnet_obj.get("reservations", []):
        if reservation.get("hw-address") == hw_address:
            return subnet_obj, reservation
    return subnet_obj, None

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
    """Search/filter/sort MAC reservations via the state index (see
    core/state_index.py) instead of the old full-config-scan-and-sort -- also
    the only way this page can now show a reservation search box and CSV
    export consistent with the Leases and Logs pages."""
    q = (request.values.get("q") or "").strip()
    subnet = (request.values.get("subnet") or "").strip()
    page, sort, direction = _pagination_params()
    sort = sort or "ip_address"
    direction = direction or "asc"
    page_size = state_index.DEFAULT_PAGE_SIZE

    conn = state_index.connect(current_app.config["STATE_INDEX_DB"])
    try:
        # Ingest is fingerprint-gated (a cheap stat check when nothing
        # changed), so refreshing inline here guarantees the page always
        # reflects the config as it is right now rather than being stale by
        # up to STATE_INDEX_INTERVAL seconds.
        state_index.ingest_all(dict(current_app.config), conn, kinds=["reservation4"])
        result = state_index.search_reservation4(
            conn, q=q or None, subnet=subnet or None,
            sort=sort, direction=direction,
            limit=page_size, offset=(page - 1) * page_size,
        )
    finally:
        conn.close()

    return render_template(
        "mac_reservations.html",
        mac_reservations=result["rows"],
        total=result["total"],
        page=page, page_size=page_size,
        has_next=(page * page_size) < result["total"],
        search_query=q, subnet=subnet, sort=sort, direction=direction,
    )


@dhcp4_bp.route("/mac-reservations/export.csv")
@login_required
def mac_reservations_export() -> Response:
    """Stream the current reservation search as CSV."""
    q = (request.values.get("q") or "").strip() or None
    subnet = (request.values.get("subnet") or "").strip() or None
    _, sort, direction = _pagination_params()
    app_config = dict(current_app.config)

    def rows():
        conn = state_index.connect(app_config["STATE_INDEX_DB"])
        try:
            state_index.ingest_all(app_config, conn, kinds=["reservation4"])
            yield from state_index.iter_search(
                conn, "reservation4", q=q, subnet=subnet,
                sort=sort or "ip_address", direction=direction or "asc",
            )
        finally:
            conn.close()

    return stream_csv_response(
        ["mac_address", "ip_address", "hostname", "subnet", "shared_network_name"],
        rows(),
        lambda row: [
            row["mac_address"] or "", row["ip_address"] or "", row["hostname"] or "",
            row["subnet"] or "", row["shared_network_name"] or "",
        ],
        "ez-kea-reservations4",
        state_index.EXPORT_MAX_ROWS,
    )

@dhcp4_bp.route("/new-reservation", methods=["GET", "POST"])
@login_required
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

        save_kea_config(config, current_app.config["DHCP_CONFIG_FILE"], current_app.config["BACKUP_DIR"])
        # Unlike logs/leases, EZ-KEA itself just wrote this reservation --
        # without an immediate reindex it wouldn't show up in a search until
        # the next background pass, which would look like the save failed.
        state_index.reindex_now(current_app, kinds=["reservation4"])
        return redirect(url_for("main.dhcp4.mac_reservations"))

    return render_template("new_reservation.html", subnet_data=subnet_data, errors=errors)

@dhcp4_bp.route("/delete-reservation", methods=["POST"])
@login_required
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
        subnet_obj, reservation = _find_reservation4(config, hw_address, subnet)
        if subnet_obj and reservation:
            subnet_obj["reservations"].remove(reservation)
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

    save_kea_config(config, current_app.config["DHCP_CONFIG_FILE"], current_app.config["BACKUP_DIR"])
    state_index.reindex_now(current_app, kinds=["reservation4"])
    return redirect(url_for("main.dhcp4.mac_reservations"))

@dhcp4_bp.route("/edit-reservation", methods=["GET", "POST"])
@login_required
@with_config_lock()
def edit_reservation() -> Union[str, Response, Tuple[str, int]]:
    """Edit an existing static MAC reservation in place. The subnet it lives
    on is locked (it's how the reservation is located); the MAC address
    itself is editable since typo fixes are a common, low-risk edit."""
    config = load_json(current_app.config["DHCP_CONFIG_FILE"])
    subnet_data = return_available_ips(config, current_app.config["DHCP_LEASES_FILE"])
    errors = []

    if request.method == "GET":
        hw_address = request.args.get("hw-address")
        subnet = request.args.get("subnet")
        subnet_obj, reservation = _find_reservation4(config, hw_address, subnet)
        if reservation is None:
            flash("Reservation not found.", "danger")
            return redirect(url_for("main.dhcp4.mac_reservations"))

        # The reservation's own IP was excluded by return_available_ips()
        # (it's "reserved" by itself) -- add it back so the edit form can
        # preselect the value it's already using.
        current_ip = reservation.get("ip-address")
        if current_ip and current_ip not in subnet_data.get(subnet, []):
            subnet_data.setdefault(subnet, []).insert(0, current_ip)

        return render_template(
            "new_reservation.html", subnet_data=subnet_data, errors=errors,
            editing=True, subnet=subnet, reservation=reservation,
        )

    # POST
    original_hw_address = request.form.get("hw-address")
    subnet = request.form.get("subnet")
    ip_address = request.form.get("ip-address")
    hostname_raw = request.form.get("hostname")
    mac_address = request.form.get("mac-address")

    if not subnet: errors.append("Subnet is required.")
    if not ip_address: errors.append("IP address is required.")
    elif not validate_ipv4_address(ip_address): errors.append("Invalid IPv4 address format for IP address.")

    hostname = sanitize_hostname(hostname_raw) if hostname_raw else ""
    if not hostname: errors.append("Hostname is required.")

    if not mac_address: errors.append("MAC is required.")
    elif not validate_mac_address(mac_address): errors.append("Invalid MAC Address format.")

    subnet_obj, reservation = None, None
    if subnet:
        subnet_obj, reservation = _find_reservation4(config, original_hw_address, subnet)
        if subnet_obj is None:
            errors.append(f"Subnet '{subnet}' was not found in the configuration.")
        elif reservation is None:
            errors.append("Reservation was not found in the configuration.")

    if not errors and mac_address != original_hw_address:
        for other in subnet_obj.get("reservations", []):
            if other is not reservation and other.get("hw-address") == mac_address:
                errors.append(f"A reservation with MAC address '{mac_address}' already exists in this subnet.")
                break

    if errors:
        fallback_reservation = {"hw-address": mac_address or original_hw_address, "hostname": hostname, "ip-address": ip_address}
        return render_template(
            "new_reservation.html", subnet_data=subnet_data, errors=errors,
            editing=True, subnet=subnet, reservation=fallback_reservation,
        ), 400

    reservation.update({
        "hostname": hostname,
        "hw-address": mac_address,
        "ip-address": ip_address,
    })

    save_kea_config(config, current_app.config["DHCP_CONFIG_FILE"], current_app.config["BACKUP_DIR"])
    return redirect(url_for("main.dhcp4.mac_reservations"))

@dhcp4_bp.route("/leases")
@login_required
def leases() -> str:
    """Search/filter/sort the DHCPv4 lease table via the state index.

    Covers every lease currently in the file, not just active ones (see
    core/state_index.py's module docstring) -- the `status` filter defaults
    to unset, so "active" is one choice among active/expired/declined/
    reclaimed rather than the only thing the page can show.
    """
    from ..core.validation import unix_to_human_readable

    q = (request.values.get("q") or "").strip()
    status = (request.values.get("status") or "").strip() or None
    subnet = (request.values.get("subnet") or "").strip() or None
    start, end, range_value = state_index.resolve_lease_time_range(
        request.values.get("range", ""), request.values.get("start", ""), request.values.get("end", "")
    )
    page, sort, direction = _pagination_params()
    sort = sort or "expire"
    direction = direction or "desc"
    page_size = state_index.DEFAULT_PAGE_SIZE

    conn = state_index.connect(current_app.config["STATE_INDEX_DB"])
    try:
        state_index.ingest_all(dict(current_app.config), conn, kinds=["lease4"])
        result = state_index.search_lease4(
            conn, q=q or None, status=status, subnet=subnet, start=start, end=end,
            sort=sort, direction=direction,
            limit=page_size, offset=(page - 1) * page_size,
        )
        stats = state_index.index_stats(conn)
    finally:
        conn.close()

    stats["last_ingest_text"] = (
        unix_to_human_readable(stats["last_ingest"]) if stats["last_ingest"] else "never"
    )

    rows = result["rows"]
    for row in rows:
        row["expiration_time"] = unix_to_human_readable(row["expire"]) if row["expire"] else "-"
        row["status"] = state_index.status_label(row["state"], row["expire"])

    return render_template(
        "leases.html",
        leases=rows,
        total=result["total"],
        page=page, page_size=page_size,
        has_next=(page * page_size) < result["total"],
        search_query=q, status=status or "", subnet=subnet or "",
        selected_range=range_value,
        start_text=request.values.get("start", "").strip(),
        end_text=request.values.get("end", "").strip(),
        time_ranges=state_index.LEASE_TIME_RANGES,
        sort=sort, direction=direction,
        stats=stats, statuses=state_index.STATUS_LABELS,
    )


@dhcp4_bp.route("/leases/export.csv")
@login_required
def leases_export() -> Response:
    """Stream the current lease search as CSV."""
    q = (request.values.get("q") or "").strip() or None
    status = (request.values.get("status") or "").strip() or None
    subnet = (request.values.get("subnet") or "").strip() or None
    start, end, _range_value = state_index.resolve_lease_time_range(
        request.values.get("range", ""), request.values.get("start", ""), request.values.get("end", "")
    )
    _, sort, direction = _pagination_params()
    app_config = dict(current_app.config)

    def rows():
        conn = state_index.connect(app_config["STATE_INDEX_DB"])
        try:
            state_index.ingest_all(app_config, conn, kinds=["lease4"])
            yield from state_index.iter_search(
                conn, "lease4", q=q, status=status, subnet=subnet, start=start, end=end,
                sort=sort or "expire", direction=direction or "desc",
            )
        finally:
            conn.close()

    from datetime import datetime

    def to_values(row):
        return [
            row["address"], row["mac_address"] or "", row["client_id"] or "",
            row["hostname"] or "", row["subnet"] or "", row["valid_lifetime"] or "",
            datetime.fromtimestamp(row["expire"]).isoformat(sep=" ") if row["expire"] else "",
            row["state"],
        ]

    return stream_csv_response(
        ["address", "mac_address", "client_id", "hostname", "subnet", "valid_lifetime", "expire", "state"],
        rows(), to_values, "ez-kea-leases4", state_index.EXPORT_MAX_ROWS,
    )