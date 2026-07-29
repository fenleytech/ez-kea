import csv
import time
import pytest
from ez_kea.core.validation import (
    classify_network_address,
    validate_mac_address,
    validate_ip_range,
    validate_ipv4_address,
    validate_duid,
    has_overlap,
    sanitize_hostname,
    validate_option_data,
    get_active_leases,
    get_active_leases6,
    return_available_ips,
)

def test_classify_network_address():
    # Valid Subnet
    assert classify_network_address("192.168.1.0/24") == 2
    # Host IP with prefix (treated as valid IP string previously, returns 1)
    assert classify_network_address("192.168.1.5/24") == 1
    # Valid single IP
    assert classify_network_address("10.0.0.1") == 2
    # Invalid strings
    assert classify_network_address("not_an_ip") == 3
    assert classify_network_address("999.999.999.999/24") == 3

def test_sanitize_hostname():
    assert sanitize_hostname("Valid-Host.name01") == "Valid-Host.name01"
    assert sanitize_hostname("Invalid_Host!@#") == "InvalidHost"
    assert sanitize_hostname("drop; tables") == "droptables"

def test_validate_mac_address():
    assert validate_mac_address("00:1A:2B:3C:4D:5E") is True
    assert validate_mac_address("00-1A-2B-3C-4D-5E") is True
    assert validate_mac_address("00:1a:2b:3c:4d:5e") is True
    assert validate_mac_address("invalid-mac") is False
    assert validate_mac_address("00:1A:2B:3C:4D:5Z") is False # Invalid hex char Z

def test_validate_ip_range():
    assert validate_ip_range("192.168.1.0/24", "192.168.1.100", "192.168.1.200") is True
    # Start after End
    assert validate_ip_range("192.168.1.0/24", "192.168.1.200", "192.168.1.100") is False
    # Outside Subnet
    assert validate_ip_range("192.168.1.0/24", "192.168.1.100", "192.168.2.100") is False

def test_validate_ip_range_ipv6():
    assert validate_ip_range("2001:db8::/64", "2001:db8::10", "2001:db8::100") is True
    assert validate_ip_range("2001:db8::/64", "2001:db8::100", "2001:db8::10") is False
    assert validate_ip_range("2001:db8::/64", "2001:db9::10", "2001:db8::100") is False

def test_validate_duid():
    assert validate_duid("00:03:00:01:aa:bb:cc:dd:ee:ff") is True
    assert validate_duid("00-03-00-01-aa-bb-cc-dd-ee-ff") is True
    assert validate_duid("00030001aabbccddeeff") is True  # continuous hex, even length
    assert validate_duid("00030001020304050") is False  # odd number of hex digits
    assert validate_duid("") is False
    assert validate_duid("zz:03:00:01") is False  # invalid hex chars
    assert validate_duid("00:03-00:01") is False  # mixed separators
    assert validate_duid("aa") is False  # single octet, too short to be a DUID
    assert validate_duid("<script>") is False
    assert validate_duid("00:" * 200 + "01") is False  # absurdly long, rejected

def test_has_overlap():
    config_data = {
        "Dhcp4": {
            "shared-networks": [
                {
                    "name": "Group1",
                    "subnet4": [{"subnet": "192.168.1.0/24"}]
                }
            ]
        }
    }
    
    # Overlapping 
    assert has_overlap("192.168.1.128/25", config_data) == "192.168.1.0/24"
    assert has_overlap("192.168.0.0/16", config_data) == "192.168.1.0/24"
    
    # Non-overlapping
    assert has_overlap("10.0.0.0/24", config_data) is False

def test_has_overlap_standalone_subnets():
    """Regression test for AUDIT_FINDINGS 2.2: has_overlap() only ever
    checked Dhcp4.shared-networks[].subnet4[], never top-level
    Dhcp4.subnet4[] (the standalone subnet list), so duplicate/overlapping
    standalone subnets were silently accepted."""
    config_data = {
        "Dhcp4": {
            "subnet4": [{"subnet": "192.168.1.0/24"}],
            "shared-networks": [],
        }
    }

    # Exact duplicate
    assert has_overlap("192.168.1.0/24", config_data) == "192.168.1.0/24"
    # Superset
    assert has_overlap("192.168.0.0/16", config_data) == "192.168.1.0/24"
    # Subset
    assert has_overlap("192.168.1.128/25", config_data) == "192.168.1.0/24"
    # Non-overlapping
    assert has_overlap("10.0.0.0/24", config_data) is False

def test_validate_ipv4_address():
    assert validate_ipv4_address("192.168.1.1") is True
    assert validate_ipv4_address("0.0.0.0") is True
    assert validate_ipv4_address("255.255.255.255") is True
    assert validate_ipv4_address("not-an-ip-address") is False
    assert validate_ipv4_address("999.999.999.999") is False
    assert validate_ipv4_address("2001:db8::1") is False
    assert validate_ipv4_address("") is False

def test_get_active_leases_skips_malformed_expire(tmp_path):
    """Regression test for AUDIT_FINDINGS 2.5: a malformed `expire` field in
    the leases CSV (e.g. from a truncated disk-full write) used to crash
    get_active_leases() with an unhandled ValueError, taking down /leases
    and /new-reservation. Malformed rows should be skipped instead."""
    leases_file = tmp_path / "leases.csv"
    with open(leases_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["address", "hwaddr", "hostname", "expire"])
        writer.writerow(["192.168.1.10", "00:11:22:33:44:55", "host1", "not-a-number"])
        writer.writerow(["192.168.1.11", "00:11:22:33:44:66", "host2", "9999999999"])

    leases = get_active_leases(str(leases_file))
    # Only the well-formed row should survive
    assert len(leases) == 1
    assert leases[0]["ip_address"] == "192.168.1.11"

def _write_leases6_csv(path, rows):
    """rows: list of dicts with keys address, duid, expire, lease_type,
    prefix_len, hostname (missing keys default to empty string)."""
    fieldnames = ["address", "duid", "valid_lifetime", "expire", "subnet_id",
                  "pref_lifetime", "lease_type", "iaid", "prefix_len",
                  "fqdn_fwd", "fqdn_rev", "hostname"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            full_row = {k: "" for k in fieldnames}
            full_row.update(row)
            writer.writerow(full_row)

def test_get_active_leases6_na_row(tmp_path):
    leases_file = tmp_path / "leases6.csv"
    _write_leases6_csv(leases_file, [
        {"address": "2001:db8::10", "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
         "expire": "9999999999", "lease_type": "0", "hostname": "laptop-01"},
    ])
    leases = get_active_leases6(str(leases_file))
    assert len(leases) == 1
    assert leases[0]["lease_type"] == "IA_NA"
    assert leases[0]["address"] == "2001:db8::10"
    assert leases[0]["prefix_len"] is None
    assert leases[0]["duid"] == "00:03:00:01:aa:bb:cc:dd:ee:ff"
    assert leases[0]["hostname"] == "laptop-01"

def test_get_active_leases6_pd_row(tmp_path):
    leases_file = tmp_path / "leases6.csv"
    _write_leases6_csv(leases_file, [
        {"address": "2001:db8:abcd::", "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
         "expire": "9999999999", "lease_type": "2", "prefix_len": "56"},
    ])
    leases = get_active_leases6(str(leases_file))
    assert len(leases) == 1
    assert leases[0]["lease_type"] == "IA_PD"
    assert leases[0]["prefix_len"] == "56"

def test_get_active_leases6_expired_row_filtered(tmp_path):
    leases_file = tmp_path / "leases6.csv"
    _write_leases6_csv(leases_file, [
        {"address": "2001:db8::10", "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
         "expire": "1", "lease_type": "0"},
    ])
    assert get_active_leases6(str(leases_file)) == []

def test_get_active_leases6_skips_malformed_expire(tmp_path):
    leases_file = tmp_path / "leases6.csv"
    _write_leases6_csv(leases_file, [
        {"address": "2001:db8::10", "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
         "expire": "not-a-number", "lease_type": "0"},
        {"address": "2001:db8::11", "duid": "00:03:00:01:aa:bb:cc:dd:ee:00",
         "expire": "9999999999", "lease_type": "0"},
    ])
    leases = get_active_leases6(str(leases_file))
    assert len(leases) == 1
    assert leases[0]["address"] == "2001:db8::11"

def test_get_active_leases6_missing_file_returns_empty():
    assert get_active_leases6("/nonexistent/leases6.csv") == []

def test_return_available_ips_includes_standalone_subnets(tmp_path):
    """Regression test for AUDIT_FINDINGS 2.2: return_available_ips() only
    ever walked Dhcp4.shared-networks[].subnet4[], so standalone subnets
    never appeared in the /new-reservation form's subnet dropdown."""
    leases_file = tmp_path / "leases.csv"
    config_data = {
        "Dhcp4": {
            "subnet4": [
                {"subnet": "192.168.5.0/29", "pools": [{"pool": "192.168.5.1 - 192.168.5.6"}]}
            ],
            "shared-networks": [],
        }
    }
    result = return_available_ips(config_data, str(leases_file))
    assert "192.168.5.0/29" in result
    assert len(result["192.168.5.0/29"]) > 0


# ── AUDIT_FINDINGS.md 1.9 — option-data sanitization ────────────────────────

def test_validate_option_data_allows_normal_values():
    assert validate_option_data("1.1.1.1, 8.8.8.8") is True
    assert validate_option_data("home.local") is True
    assert validate_option_data("http://acs.example.com/cwmp") is True

def test_validate_option_data_rejects_script_tag():
    """Live-tested payload from AUDIT_FINDINGS.md 1.9."""
    assert validate_option_data("<script>alert(document.cookie)</script>") is False

def test_validate_option_data_rejects_control_characters():
    assert validate_option_data("value\x00withnull") is False
    assert validate_option_data("value\nwith\nnewlines\rand\rcr") is False

def test_validate_option_data_rejects_empty():
    assert validate_option_data("") is False


# ── AUDIT_FINDINGS.md 1.10 — sanitize_hostname() applied to lease hostnames ─

def test_get_active_leases_sanitizes_hostname(tmp_path):
    leases_file = tmp_path / "kea-leases4.csv"
    future = int(time.time()) + 3600
    leases_file.write_text(
        "address,hwaddr,hostname,expire\n"
        f'192.168.1.50,00:11:22:33:44:55,"<script>alert(1)</script>",{future}\n'
    )
    leases = get_active_leases(str(leases_file))
    assert len(leases) == 1
    # Angle brackets/parens/slashes must all be stripped, same as the sanitizer
    # already applied to human-typed hostnames in new_reservation().
    assert "<" not in leases[0]["hostname"]
    assert ">" not in leases[0]["hostname"]
    assert leases[0]["hostname"] == sanitize_hostname("<script>alert(1)</script>")
