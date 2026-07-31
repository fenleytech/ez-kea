# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import ipaddress
from ipaddress import IPv4Network
import re
import warnings
import time
import csv
from typing import Any, Dict, List, Set, Union

def classify_network_address(address: str) -> int:
    """
    Classify a network address string.
    Returns:
        1: Host IP with netmask
        2: Valid network or bare IP
        3: Invalid network address
    """
    try:
        network = ipaddress.ip_network(address, strict=False)
        # If address contains a host bit (e.g. 192.168.1.5/24), it's a host IP with prefix
        if '/' in address and ipaddress.ip_interface(address).ip != network.network_address:
            return 1  # Host IP with netmask — not a clean network address
        return 2  # Valid network
    except (ValueError, ipaddress.AddressValueError):
        try:
            ipaddress.ip_address(address)
            return 2  # Valid bare IP
        except:
            return 3  # Invalid

def sanitize_hostname(hostname: str) -> str:
    """Sanitize hostname by keeping only alphanumeric chars, hyphens, and dots."""
    # Keep only allowed chars: alphanumeric, hyphens, dots
    allowed_chars = re.compile(r'[^a-zA-Z0-9\-.]')
    return allowed_chars.sub('', hostname)

_CONTROL_CHAR_RE = re.compile(r'[\x00-\x1f\x7f]')

def validate_option_data(value: str) -> bool:
    """
    Reject DHCP option-data (and option-name) values containing control
    characters or angle brackets. This is DHCP option data serialized into a
    config file real DHCP clients parse, not free-form HTML — control chars
    can break the Kea config/log format and angle brackets have no legitimate
    use here.
    """
    if not isinstance(value, str) or not value:
        return False
    if _CONTROL_CHAR_RE.search(value):
        return False
    if '<' in value or '>' in value:
        return False
    return True

def validate_mac_address(mac_address: str) -> bool:
    """Check if the provided string is a valid MAC address format."""
    pattern = r"^([0-9A-Fa-f]{2}([:-])){5}[0-9A-Fa-f]{2}$"
    try:
        warnings.filterwarnings("ignore", category=FutureWarning)
        return bool(re.match(pattern, mac_address))
    except ModuleNotFoundError:
        return bool(re.match(pattern, mac_address))

_DUID_OCTET_RE = re.compile(r'^[0-9A-Fa-f]{2}$')
_DUID_HEX_RE = re.compile(r'^[0-9A-Fa-f]+$')

def validate_duid(duid: str) -> bool:
    """
    Check if the provided string is a plausible Kea DUID: colon- or
    hyphen-separated hex octets (e.g. "00:03:00:01:aa:bb:cc:dd:ee:ff"), or
    one continuous hex string. RFC 8415 defines specific DUID-LLT/EN/LL/UUID
    layouts, but Kea also accepts an arbitrary "flexible" DUID, so this
    validates the general octet-string shape (an even number of hex digits,
    long enough to hold at least the 2-byte type field) rather than one
    specific DUID type.
    """
    if not isinstance(duid, str) or not duid:
        return False
    if _CONTROL_CHAR_RE.search(duid) or '<' in duid or '>' in duid:
        return False

    has_colon = ':' in duid
    has_hyphen = '-' in duid
    if has_colon and has_hyphen:
        return False  # Don't accept a mix of separators.

    if has_colon or has_hyphen:
        octets = duid.split(':' if has_colon else '-')
        if any(not _DUID_OCTET_RE.match(o) for o in octets):
            return False
        octet_count = len(octets)
    else:
        if len(duid) % 2 != 0 or not _DUID_HEX_RE.match(duid):
            return False
        octet_count = len(duid) // 2

    return 2 <= octet_count <= 130

def validate_ipv4_address(ip_address: str) -> bool:
    """Check if the provided string is a syntactically valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip_address)
        return True
    except (ValueError, TypeError):
        return False

def validate_ip_range(subnet: str, range_start: str, range_end: str) -> bool:
    """Validate that start and end IPs are within the subnet and start < end."""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        start_ip = ipaddress.ip_address(range_start)
        end_ip = ipaddress.ip_address(range_end)
        if start_ip not in network or end_ip not in network:
            return False
        return start_ip < end_ip
    except (ValueError, ipaddress.AddressValueError):
        return False

def has_overlap(new_subnet: str, data: Dict[str, Any], prefix: str = "Dhcp4") -> Union[str, bool]:
    """
    Check if a new subnet overlaps with any existing subnets in the config.
    Checks both standalone top-level subnets (Dhcp4.subnet4[]/Dhcp6.subnet6[])
    and subnets nested inside shared-networks.
    Returns the overlapping subnet string if it exists, otherwise False.
    """
    try:
        new_network = ipaddress.ip_network(new_subnet)
    except ValueError:
         return False

    subnet_key = "subnet4" if prefix == "Dhcp4" else "subnet6"

    if prefix in data:
        # Standalone subnets declared directly under Dhcp4/Dhcp6
        for existing_subnet in data[prefix].get(subnet_key, []):
            try:
                existing_network = ipaddress.ip_network(existing_subnet["subnet"])
                if existing_network.overlaps(new_network):
                    return existing_network.exploded
            except ValueError:
                continue

        # Subnets nested inside shared-networks
        for shared_network in data[prefix].get("shared-networks", []):
            for existing_subnet in shared_network.get(subnet_key, []):
                try:
                    existing_network = ipaddress.ip_network(existing_subnet["subnet"])
                    if existing_network.overlaps(new_network):
                        return existing_network.exploded
                except ValueError:
                     continue
    return False

def get_active_leases(leases_file: str) -> List[Dict[str, Any]]:
    """Return a list of active DHCP leases parsed from the Kea leases CSV."""
    active_leases = []
    seen_ips = set()
    current_time = int(time.time())
    
    try:
        with open(leases_file, "r") as file:
            reader = csv.DictReader(file)
            for row in reader:
                try:
                    expiration_time = int(row.get("expire", 0))
                except (ValueError, TypeError):
                    # Malformed/corrupted expire field (e.g. from a truncated
                    # disk-full write) — skip this row instead of crashing
                    # the whole leases list.
                    continue
                address = row.get("address")
                if expiration_time > current_time and address not in seen_ips:
                    seen_ips.add(address)
                    active_leases.append({
                        "ip_address": address,
                        "mac_address": row.get("hwaddr"),
                        # Hostnames here come straight from whatever the DHCP client
                        # sent in its hostname option — sanitize the same way a
                        # human-typed hostname is sanitized.
                        "hostname": sanitize_hostname(row.get("hostname") or ""),
                        "expire": expiration_time
                    })
    except FileNotFoundError:
        pass
    return active_leases

# Kea's lease6 memfile CSV "lease_type" column: 0=IA_NA, 1=IA_TA, 2=IA_PD.
_LEASE6_TYPE_LABELS = {"0": "IA_NA", "1": "IA_TA", "2": "IA_PD"}

def get_active_leases6(leases_file: str) -> List[Dict[str, Any]]:
    """
    Return a list of active DHCPv6 leases parsed from Kea's lease6 CSV.

    Kea's lease6 schema differs from lease4's (duid instead of hwaddr,
    subnet_id/pref_lifetime/lease_type/iaid/prefix_len columns that lease4
    doesn't have) so this is a separate parser rather than a version branch
    inside get_active_leases(). lease_type distinguishes IA_NA/IA_TA (a plain
    host address, in `address`) from IA_PD (a delegated prefix, whose first
    address is in `address` with its length in `prefix_len`).
    """
    active_leases = []
    seen_addresses = set()
    current_time = int(time.time())

    try:
        with open(leases_file, "r") as file:
            reader = csv.DictReader(file)
            for row in reader:
                try:
                    expiration_time = int(row.get("expire", 0))
                except (ValueError, TypeError):
                    # Malformed/corrupted expire field — skip this row
                    # instead of crashing the whole leases list.
                    continue
                address = row.get("address")
                if expiration_time > current_time and address not in seen_addresses:
                    seen_addresses.add(address)
                    lease_type_label = _LEASE6_TYPE_LABELS.get(row.get("lease_type", "0"), "IA_NA")
                    active_leases.append({
                        "address": address,
                        "prefix_len": row.get("prefix_len") if lease_type_label == "IA_PD" else None,
                        "duid": row.get("duid"),
                        "hostname": sanitize_hostname(row.get("hostname") or ""),
                        "expire": expiration_time,
                        "lease_type": lease_type_label,
                    })
    except FileNotFoundError:
        pass
    return active_leases

def _iter_subnet4_lists(config_data: Dict[str, Any]) -> List[List[Dict[str, Any]]]:
    """Return every subnet4 list in the config: the standalone top-level list
    (Dhcp4.subnet4[]) plus each shared-network's own subnet4[] list."""
    dhcp4 = config_data.get("Dhcp4", {})
    lists = []
    if "subnet4" in dhcp4:
        lists.append(dhcp4["subnet4"])
    for shared_network in dhcp4.get("shared-networks", []):
        if "subnet4" in shared_network:
            lists.append(shared_network["subnet4"])
    return lists

def return_available_ips(config_data: Dict[str, Any], leases_file: str) -> Dict[str, List[str]]:
    """Calculate and return available IP addresses per subnet.
    Covers both standalone subnets (Dhcp4.subnet4[]) and subnets nested
    inside shared-networks."""
    subnet_data: Dict[str, List[str]] = {}
    reserved_ips = set()
    active_leases_ips = set(lease['ip_address'] for lease in get_active_leases(leases_file))

    if "Dhcp4" not in config_data:
         return subnet_data

    subnet4_lists = _iter_subnet4_lists(config_data)

    for subnet4_list in subnet4_lists:
        for subnet in subnet4_list:
            if "reservations" in subnet:
                for reservation in subnet["reservations"]:
                    if "ip-address" in reservation:
                        reserved_ips.add(reservation["ip-address"])

    for subnet4_list in subnet4_lists:
        for subnet in subnet4_list:
            router_address = None
            if "option-data" in subnet:
                 for option in subnet["option-data"]:
                      if option.get("name") == "routers":
                           router_address = option.get("data")
                           break

            available_ips = []
            try:
                network = ipaddress.ip_network(subnet["subnet"])
                for ip in network.hosts():
                    ip_str = str(ip)
                    if (ip_str not in reserved_ips
                        and ip_str not in active_leases_ips
                        and ip_str != router_address):
                        available_ips.append(ip_str)
                subnet_data[subnet["subnet"]] = available_ips
            except ValueError:
                 continue
    return subnet_data

def human_readable_time(seconds: int) -> str:
    """Convert an integer of seconds into a human readable description."""
    periods = [
        ("week", 60 * 60 * 24 * 7),
        ("day", 60 * 60 * 24),
        ("hour", 60 * 60),
        ("minute", 60),
    ]
    for period_name, period_seconds in periods:
        if seconds >= period_seconds:
            period_value, remainder = divmod(seconds, period_seconds)
            return f"{period_value} {period_name}{'s' if period_value > 1 else ''}"
    return f"{seconds} seconds"

def unix_to_human_readable(timestamp: Union[int, str, float]) -> str:
    """Convert a UNIX timestamp to a localized human-readable string."""
    try:
        timestamp = int(timestamp)
    except ValueError:
        return "Invalid Timestamp"
    import datetime
    return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %I:%M:%S %p")
