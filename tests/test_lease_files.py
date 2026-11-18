# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
tests/test_lease_files.py

Kea's lease file cleanup (LFC) moves the leases out of the main memfile CSV
into `<file>.2`, leaving the main file with only its header. EZ-KEA read
only the main file, so after every LFC pass (hourly with lfc-interval 3600)
the dashboard showed ~0 active leases. Reproduced on a live Kea 3.2.1 box,
2026-11-17: 14 unexpired leases in kea-leases4.csv.2, header only in
kea-leases4.csv, dashboard said 0.
"""
import csv
import os
import time

import pytest

from ez_kea.core import lease_files
from ez_kea.core import state_index as si
from ez_kea.core.validation import get_active_leases, get_active_leases6, return_available_ips

HEADER4 = [
    "address", "hwaddr", "client_id", "valid_lifetime", "expire", "subnet_id",
    "fqdn_fwd", "fqdn_rev", "hostname", "state", "user_context", "pool_id",
]
HEADER6 = [
    "address", "duid", "valid_lifetime", "expire", "subnet_id", "pref_lifetime",
    "lease_type", "iaid", "prefix_len", "fqdn_fwd", "fqdn_rev", "hostname",
    "hwaddr", "state", "user_context", "pool_id",
]
FUTURE = int(time.time()) + 3600
PAST = int(time.time()) - 3600


def lease4(address, expire=FUTURE, state=0, mac="00:11:22:33:44:55", hostname=""):
    return [address, mac, "", "3600", str(expire), "1", "0", "0", hostname, str(state), "", "0"]


def lease6(address, expire=FUTURE, state=0):
    return [address, "00:01:02", "3600", str(expire), "1", "1800", "0", "1", "128",
            "0", "0", "", "", str(state), "", "0"]


def write(path, header, rows):
    with open(path, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


@pytest.fixture
def leases(tmp_path):
    return str(tmp_path / "kea-leases4.csv")


def test_after_lfc_leases_in_dot2_are_active(leases):
    write(leases + ".2", HEADER4, [lease4(f"10.0.0.{i}") for i in range(1, 15)])
    write(leases, HEADER4, [])

    assert len(get_active_leases(leases)) == 14


def test_during_lfc_dot1_is_read_too(leases):
    write(leases + ".2", HEADER4, [lease4("10.0.0.1")])
    write(leases + ".1", HEADER4, [lease4("10.0.0.2")])
    write(leases, HEADER4, [lease4("10.0.0.3")])

    assert {l["ip_address"] for l in get_active_leases(leases)} == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}


def test_completed_replaces_dot1_and_dot2(leases):
    """An LFC that finished but didn't rotate leaves .completed; Kea loads it
    instead of .1/.2, and so must we."""
    write(leases + ".completed", HEADER4, [lease4("10.0.0.1")])
    write(leases + ".2", HEADER4, [lease4("10.0.0.9")])
    write(leases + ".1", HEADER4, [lease4("10.0.0.8")])
    write(leases, HEADER4, [])

    assert lease_files.lease_file_set(leases) == [leases + ".completed", leases]
    assert [l["ip_address"] for l in get_active_leases(leases)] == ["10.0.0.1"]


def test_newer_row_in_main_file_overrides_dot2(leases):
    """A lease active in .2 but released (reclaimed) since must not count."""
    write(leases + ".2", HEADER4, [lease4("10.0.0.1"), lease4("10.0.0.2")])
    write(leases, HEADER4, [lease4("10.0.0.1", expire=PAST, state=2)])

    assert [l["ip_address"] for l in get_active_leases(leases)] == ["10.0.0.2"]


def test_last_row_wins_within_one_file(leases):
    """The old reader kept the *first* unexpired row, so a lease released
    after being granted still counted as active."""
    write(leases, HEADER4, [lease4("10.0.0.1"), lease4("10.0.0.1", expire=PAST, state=2)])

    assert get_active_leases(leases) == []


def test_declined_is_not_active_but_not_available(leases):
    write(leases, HEADER4, [lease4("192.168.5.1", state=1)])
    config = {"Dhcp4": {"subnet4": [{"subnet": "192.168.5.0/29"}]}}

    assert get_active_leases(leases) == []
    assert "192.168.5.1" not in return_available_ips(config, leases)["192.168.5.0/29"]


def test_v6_reads_dot2(tmp_path):
    path = str(tmp_path / "kea-leases6.csv")
    write(path + ".2", HEADER6, [lease6("2001:db8::1"), lease6("2001:db8::2")])
    write(path, HEADER6, [])

    assert {l["address"] for l in get_active_leases6(path)} == {"2001:db8::1", "2001:db8::2"}


def test_missing_store_is_empty(tmp_path):
    path = str(tmp_path / "nope.csv")
    assert lease_files.lease_file_set(path) == []
    assert get_active_leases(path) == []
    assert lease_files.fingerprint(path) == lease_files.fingerprint(path)


def test_dashboard_count_survives_lfc_rotation(tmp_path):
    """End to end through the state index that feeds the dashboard card,
    including the fingerprint noticing the rotation."""
    path = str(tmp_path / "kea-leases4.csv")
    config = {
        "DHCP_LEASES_FILE": path,
        "DHCP6_LEASES_FILE": str(tmp_path / "kea-leases6.csv"),
        "DHCP_CONFIG_FILE": str(tmp_path / "kea-dhcp4.conf"),
        "DHCP6_CONFIG_FILE": str(tmp_path / "kea-dhcp6.conf"),
    }
    rows = [lease4(f"10.0.0.{i}") for i in range(1, 15)]
    write(path, HEADER4, rows)
    conn = si.connect(str(tmp_path / "state.db"))
    try:
        si.ingest_all(config, conn)
        assert si.active_lease_counts(conn)["lease4"] == 14

        # LFC: main -> .1, fresh header-only main, compacted output -> .2, .1 removed.
        os.rename(path, path + ".1")
        write(path, HEADER4, [])
        write(path + ".2", HEADER4, rows)
        os.remove(path + ".1")

        assert si.ingest_all(config, conn)["lease4"] is True
        assert si.active_lease_counts(conn)["lease4"] == 14
    finally:
        conn.close()
