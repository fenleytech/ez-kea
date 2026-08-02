# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
tests/test_state_index.py

Covers the searchable lease/reservation index: CSV/config parsing (including
last-occurrence-wins dedup), fingerprint-gated reingest, indexed search
across all four kinds, and CSV export.
"""
import csv
import json
import time

import pytest

from ez_kea.core import state_index as si


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

LEASE4_HEADER = [
    "address", "hwaddr", "client_id", "valid_lifetime", "expire", "subnet_id",
    "fqdn_fwd", "fqdn_rev", "hostname", "state", "user_context", "pool_id",
]
LEASE6_HEADER = [
    "address", "duid", "valid_lifetime", "expire", "subnet_id", "pref_lifetime",
    "lease_type", "iaid", "prefix_len", "fqdn_fwd", "fqdn_rev", "hostname",
    "hwaddr", "state", "user_context", "pool_id",
]


def write_csv(path, header, rows):
    with open(path, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


@pytest.fixture
def paths(tmp_path):
    return {
        "lease4": str(tmp_path / "leases4.csv"),
        "lease6": str(tmp_path / "leases6.csv"),
        "config4": str(tmp_path / "kea-dhcp4.conf"),
        "config6": str(tmp_path / "kea-dhcp6.conf"),
        "db": str(tmp_path / "state.db"),
    }


@pytest.fixture
def config(paths):
    return {
        "DHCP_LEASES_FILE": paths["lease4"],
        "DHCP6_LEASES_FILE": paths["lease6"],
        "DHCP_CONFIG_FILE": paths["config4"],
        "DHCP6_CONFIG_FILE": paths["config6"],
        "STATE_INDEX_DB": paths["db"],
    }


@pytest.fixture
def conn(paths):
    connection = si.connect(paths["db"])
    yield connection
    connection.close()


def write_config4(path, subnets=None, shared_networks=None):
    with open(path, "w") as handle:
        json.dump({"Dhcp4": {"subnet4": subnets or [], "shared-networks": shared_networks or []}}, handle)


def write_config6(path, subnets=None, shared_networks=None):
    with open(path, "w") as handle:
        json.dump({"Dhcp6": {"subnet6": subnets or [], "shared-networks": shared_networks or []}}, handle)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def test_parse_lease4_keeps_last_occurrence_per_address(paths):
    write_csv(paths["lease4"], LEASE4_HEADER, [
        ["10.0.0.5", "aa:bb:cc:dd:ee:ff", "", "4000", "1000000000", "1", "0", "0", "old-name", "0", "", ""],
        ["10.0.0.5", "aa:bb:cc:dd:ee:ff", "", "4000", "9999999999", "1", "0", "0", "new-name", "0", "", ""],
    ])
    rows = si.parse_lease4(paths["lease4"])
    assert len(rows) == 1
    assert rows[0]["hostname"] == "new-name"
    assert rows[0]["expire"] == 9999999999


def test_parse_lease4_skips_malformed_expire(paths):
    write_csv(paths["lease4"], LEASE4_HEADER, [
        ["10.0.0.6", "11:22:33:44:55:66", "", "4000", "not-a-number", "1", "0", "0", "", "0", "", ""],
    ])
    assert si.parse_lease4(paths["lease4"]) == []


def test_parse_lease4_missing_file_returns_empty(paths):
    assert si.parse_lease4(paths["lease4"]) == []


def test_parse_lease6_distinguishes_prefix_delegation(paths):
    write_csv(paths["lease6"], LEASE6_HEADER, [
        ["2001:db8::", "00:01:00:01:aa:bb", "4000", "9999999999", "1", "3600", "2", "1", "56",
         "0", "0", "", "", "0", "", ""],
    ])
    rows = si.parse_lease6(paths["lease6"])
    assert len(rows) == 1
    assert rows[0]["prefix_len"] == 56
    assert rows[0]["lease_type"] == 2


def test_parse_reservation4_covers_standalone_and_shared(paths):
    write_config4(
        paths["config4"],
        subnets=[{"id": 1, "subnet": "10.0.0.0/24", "reservations": [
            {"hw-address": "AA:BB:CC:DD:EE:FF", "ip-address": "10.0.0.10", "hostname": "standalone-host"},
        ]}],
        shared_networks=[{"name": "office", "subnet4": [{"id": 2, "subnet": "10.0.1.0/24", "reservations": [
            {"hw-address": "11:22:33:44:55:66", "ip-address": "10.0.1.10", "hostname": "shared-host"},
        ]}]}],
    )
    with open(paths["config4"]) as handle:
        config = json.load(handle)
    rows = si.parse_reservation4(config)
    assert len(rows) == 2
    by_hostname = {row["hostname"]: row for row in rows}
    assert by_hostname["standalone-host"]["shared_network_name"] is None
    assert by_hostname["standalone-host"]["mac_address"] == "aa:bb:cc:dd:ee:ff"
    assert by_hostname["shared-host"]["shared_network_name"] == "office"


def test_parse_reservation6_covers_address_and_prefix(paths):
    write_config6(paths["config6"], subnets=[{"subnet": "2001:db8::/64", "reservations": [
        {"duid": "00:01:00:01:aa:bb", "hostname": "addr-host", "ip-addresses": ["2001:db8::10"]},
        {"duid": "00:01:00:01:cc:dd", "hostname": "prefix-host", "prefixes": ["2001:db8:1::/56"]},
    ]}])
    with open(paths["config6"]) as handle:
        config = json.load(handle)
    rows = si.parse_reservation6(config)
    by_hostname = {row["hostname"]: row for row in rows}
    assert by_hostname["addr-host"]["ip_address"] == "2001:db8::10"
    assert by_hostname["prefix-host"]["prefix"] == "2001:db8:1::/56"


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------

def test_ingest_all_skips_unchanged_sources(config, paths, conn):
    write_csv(paths["lease4"], LEASE4_HEADER, [
        ["10.0.0.5", "aa:bb:cc:dd:ee:ff", "", "4000", "9999999999", "1", "0", "0", "", "0", "", ""],
    ])
    write_config4(paths["config4"])
    write_config6(paths["config6"])

    first = si.ingest_all(config, conn)
    assert first["lease4"] is True

    second = si.ingest_all(config, conn)
    assert second["lease4"] is False


def test_ingest_all_reingests_after_file_changes(config, paths, conn):
    write_csv(paths["lease4"], LEASE4_HEADER, [])
    write_config4(paths["config4"])
    write_config6(paths["config6"])
    si.ingest_all(config, conn)

    time.sleep(0.01)  # mtime resolution
    write_csv(paths["lease4"], LEASE4_HEADER, [
        ["10.0.0.7", "aa:aa:aa:aa:aa:aa", "", "4000", "9999999999", "1", "0", "0", "", "0", "", ""],
    ])
    result = si.ingest_all(config, conn)
    assert result["lease4"] is True
    assert si.search_lease4(conn)["total"] == 1


def test_ingest_all_kinds_filter_only_touches_requested_table(config, paths, conn):
    write_csv(paths["lease4"], LEASE4_HEADER, [
        ["10.0.0.5", "aa:bb:cc:dd:ee:ff", "", "4000", "9999999999", "1", "0", "0", "", "0", "", ""],
    ])
    write_config4(paths["config4"])
    write_config6(paths["config6"])
    result = si.ingest_all(config, conn, kinds=["reservation4"])
    assert set(result.keys()) == {"reservation4"}
    assert si.search_lease4(conn)["total"] == 0  # lease4 never ingested


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

@pytest.fixture
def populated(config, paths, conn):
    write_csv(paths["lease4"], LEASE4_HEADER, [
        ["10.0.0.5", "aa:bb:cc:dd:ee:ff", "", "4000", str(int(time.time()) + 3600), "1", "0", "0",
         "active-host", "0", "", ""],
        ["10.0.0.6", "bb:bb:bb:bb:bb:bb", "", "4000", str(int(time.time()) - 3600), "2", "0", "0",
         "expired-host", "0", "", ""],
        ["10.0.0.7", "cc:cc:cc:cc:cc:cc", "", "4000", str(int(time.time()) + 3600), "1", "0", "0",
         "declined-host", "1", "", ""],
    ])
    write_config4(paths["config4"], subnets=[{"id": 1, "subnet": "10.0.0.0/24", "reservations": [
        {"hw-address": "11:22:33:44:55:66", "ip-address": "10.0.0.50", "hostname": "res-host"},
    ]}])
    write_config6(paths["config6"])
    si.ingest_all(config, conn)
    return conn


def test_search_lease4_by_ip(populated):
    result = si.search_lease4(populated, ip="10.0.0.5")
    assert result["total"] == 1
    assert result["rows"][0]["hostname"] == "active-host"


def test_search_lease4_by_mac_auto_detected(populated):
    result = si.search_lease4(populated, q="AA:BB:CC:DD:EE:FF")
    assert result["total"] == 1
    assert result["rows"][0]["address"] == "10.0.0.5"


def test_search_lease4_status_active_excludes_past_expiry(populated):
    result = si.search_lease4(populated, status="active")
    hostnames = {row["hostname"] for row in result["rows"]}
    assert hostnames == {"active-host"}


def test_search_lease4_status_expired(populated):
    result = si.search_lease4(populated, status="expired")
    assert {row["hostname"] for row in result["rows"]} == {"expired-host"}


def test_search_lease4_status_declined(populated):
    result = si.search_lease4(populated, status="declined")
    assert {row["hostname"] for row in result["rows"]} == {"declined-host"}


def test_search_lease4_subnet_id_filter(populated):
    result = si.search_lease4(populated, subnet_id=2)
    assert result["total"] == 1
    assert result["rows"][0]["hostname"] == "expired-host"


def test_search_lease4_uninterpretable_mac_returns_empty(populated):
    result = si.search_lease4(populated, mac="not-a-mac-and-not-hex")
    assert result == {"rows": [], "total": 0, "limit": 100, "offset": 0}


def test_search_reservation4_by_mac(populated):
    result = si.search_reservation4(populated, q="11:22:33:44:55:66")
    assert result["total"] == 1
    assert result["rows"][0]["ip_address"] == "10.0.0.50"


def test_search_reservation4_by_subnet(populated):
    result = si.search_reservation4(populated, subnet="10.0.0.0/24")
    assert result["total"] == 1


def test_search_lease4_sort_direction(populated):
    asc = si.search_lease4(populated, sort="address", direction="asc")
    desc = si.search_lease4(populated, sort="address", direction="desc")
    assert [r["address"] for r in asc["rows"]] == list(reversed([r["address"] for r in desc["rows"]]))


def test_status_label_reflects_state_and_expiry():
    now = int(time.time())
    assert si.status_label(0, now + 100) == "active"
    assert si.status_label(0, now - 100) == "expired"
    assert si.status_label(1, now + 100) == "declined"
    assert si.status_label(2, now + 100) == "reclaimed"


def test_iter_search_paginates_across_pages(populated):
    rows = list(si.iter_search(populated, "lease4", page_size=1))
    assert len(rows) == 3


def test_index_stats_counts_rows(populated):
    stats = si.index_stats(populated)
    assert stats["lease4"] == 3
    assert stats["reservation4"] == 1
    assert stats["last_ingest"] is not None
