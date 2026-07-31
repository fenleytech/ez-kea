#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
demo/seed_demo.py — build the public demo's data set from scratch.

Writes a self-contained, entirely synthetic "mid-size office" Kea environment
into a target data directory: DHCPv4 + DHCPv6 configs, active lease CSVs, log
files, and a fresh EZ-Kea database holding a single known demo account.

Everything here is fabricated. No real MAC address, hostname, DUID, or subnet
from any live network appears in this file, which is the entire point: the
public demo must never expose a real network's inventory.

Because it rebuilds the whole data set every run, this doubles as the reset
mechanism for the public demo — see demo/reset_demo.sh, which just calls it on
a timer. Lease expiry times are generated relative to "now" on each run, so a
reset also refreshes leases that would otherwise age out and leave the Leases
page empty.

Usage:
    python3 demo/seed_demo.py                      # seed ./data
    python3 demo/seed_demo.py --target /srv/ez-kea-demo/data
    python3 demo/seed_demo.py --demo-password hunter2
"""
import argparse
import csv
import glob
import gzip
import json
import os
import random
import sys
from datetime import datetime, timedelta

# Import the app's own models so the seeded DB always matches the live schema
# rather than a hand-rolled CREATE TABLE that silently drifts.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Fixed seed: the demo should look identical after every reset, so screenshots
# in the README/wiki don't go stale and support questions stay reproducible.
RNG = random.Random(20260729)

DEFAULT_DEMO_USERNAME = "demo"
DEFAULT_DEMO_PASSWORD = "demo"

# Days of log history the demo ships with, written out as a live log plus
# rotated siblings the way logrotate would leave them. A 45-minute tail was
# enough to show the Logs page had colour coding; it is nowhere near enough to
# show what the log search is for, which is answering "who held this address
# three weeks ago" — so the demo carries a month, including gzipped archives,
# to exercise the index's rotation handling too.
LOG_HISTORY_DAYS = 30
LOG_LINES_PER_HISTORY_DAY = 140

# Above 100 active leases EZ-Kea shows a licensing reminder banner (see
# ez_kea/license.py NAG_LEASE_THRESHOLD). Nothing is blocked, but the demo
# sits well under it so visitors see the product, not a licensing notice.
TARGET_ACTIVE_LEASES4 = 62

DNS_PRIMARY = "10.20.10.10"
DNS_SECONDARY = "10.20.10.11"
DOMAIN_NAME = "corp.example.com"
NTP_SERVER = "10.20.10.10"
ACS_URL = "http://acs.corp.example.com:7547/acs"

# ── Subnet plan ─────────────────────────────────────────────────────────────
# id, cidr, pool start/end, gateway, label used for lease hostnames.
SUBNETS4 = [
    {"id": 1, "net": "10.20.10", "cidr": "10.20.10.0/24", "pool": ("10.20.10.50", "10.20.10.200"),
     "gw": "10.20.10.1", "network": "corp-campus"},
    {"id": 2, "net": "10.20.20", "cidr": "10.20.20.0/24", "pool": ("10.20.20.50", "10.20.20.200"),
     "gw": "10.20.20.1", "network": "corp-campus"},
    {"id": 3, "net": "10.20.30", "cidr": "10.20.30.0/24", "pool": ("10.20.30.50", "10.20.30.200"),
     "gw": "10.20.30.1", "network": "voice-vlan30"},
    {"id": 4, "net": "10.20.40", "cidr": "10.20.40.0/24", "pool": ("10.20.40.50", "10.20.40.240"),
     "gw": "10.20.40.1", "network": "guest-wifi"},
    {"id": 5, "net": "192.168.50", "cidr": "192.168.50.0/24", "pool": ("192.168.50.100", "192.168.50.180"),
     "gw": "192.168.50.1", "network": None},
]

# Reservations, keyed by the subnet id they belong to.
RESERVATIONS4 = {
    1: [
        {"hw-address": "00:1b:63:84:45:e6", "ip-address": "10.20.10.21", "hostname": "printer-hr-01"},
        {"hw-address": "00:25:90:0c:1f:33", "ip-address": "10.20.10.22", "hostname": "nas-backup-01"},
        {"hw-address": "3c:07:54:19:aa:b2", "ip-address": "10.20.10.23", "hostname": "conf-room-a-tv"},
    ],
    2: [
        {"hw-address": "18:64:72:5d:0e:91", "ip-address": "10.20.20.31", "hostname": "ap-floor2-03"},
        {"hw-address": "18:64:72:5d:0e:92", "ip-address": "10.20.20.32", "hostname": "ap-floor2-04"},
    ],
    3: [
        {"hw-address": "00:04:f2:aa:31:7c", "ip-address": "10.20.30.41", "hostname": "phone-reception"},
        {"hw-address": "00:04:f2:aa:31:7d", "ip-address": "10.20.30.42", "hostname": "phone-conf-a"},
    ],
    5: [
        {"hw-address": "b8:27:eb:14:6f:20", "ip-address": "192.168.50.11", "hostname": "sw-core-01"},
        {"hw-address": "b8:27:eb:14:6f:21", "ip-address": "192.168.50.12", "hostname": "fw-edge-01"},
    ],
}

# ── IPv6 plan ───────────────────────────────────────────────────────────────
# All v6 subnets live inside shared networks on purpose: the Pools (IPv6) view
# only renders shared-network subnets, so a standalone subnet6 would be written
# to disk but never shown in the UI.
#
# 2001:db8::/32 is the RFC 3849 documentation prefix — correct for a demo and
# unroutable on the public internet.
SUBNETS6 = [
    {"id": 1, "cidr": "2001:db8:10::/64", "pool": ("2001:db8:10::100", "2001:db8:10::1ff"),
     "network": "corp-campus-v6"},
    {"id": 2, "cidr": "2001:db8:20::/64", "pool": ("2001:db8:20::100", "2001:db8:20::1ff"),
     "network": "corp-campus-v6"},
    {"id": 3, "cidr": "2001:db8:30::/64", "pool": ("2001:db8:30::100", "2001:db8:30::1ff"),
     "network": "voice-vlan30-v6"},
    {"id": 4, "cidr": "2001:db8:40::/64", "pool": ("2001:db8:40::100", "2001:db8:40::1ff"),
     "network": "branch-pd-v6", "pd": ("2001:db8:4000::/48", 56)},
]

RESERVATIONS6 = {
    1: [
        {"duid": "00:03:00:01:00:1b:63:84:45:e6", "ip-addresses": ["2001:db8:10::21"],
         "hostname": "printer-hr-01"},
        {"duid": "00:03:00:01:00:25:90:0c:1f:33", "ip-addresses": ["2001:db8:10::22"],
         "hostname": "nas-backup-01"},
    ],
    3: [
        {"duid": "00:03:00:01:00:04:f2:aa:31:7c", "ip-addresses": ["2001:db8:30::41"],
         "hostname": "phone-reception"},
    ],
    4: [
        {"duid": "00:03:00:01:5c:5e:ab:11:02:44", "prefixes": ["2001:db8:4000:100::/56"],
         "hostname": "cpe-branch-office-01"},
    ],
}

# Vendor OUI pool for generated lease MACs. These are real, publicly allocated
# OUIs paired with random device halves, so the table looks like a plausible
# office rather than a column of identical prefixes.
OUIS = ["3c:07:54", "18:64:72", "00:25:90", "b8:27:eb", "00:1b:63", "f0:9f:c2", "dc:a6:32", "00:04:f2"]

# Device-name pools per subnet id. Keeping these subnet-appropriate matters
# for the screenshots: a "phone-01" showing up on the workstation VLAN reads as
# obviously generated data, which undercuts the point of a realistic demo.
HOSTNAME_POOLS = {
    1: ["desktop", "laptop", "printer", "scanner", "badge-reader", "timeclock"],
    2: ["laptop", "tablet", "desktop", "kiosk", "handheld"],
    3: ["phone", "conf-phone", "softphone-pc", "paging-gw"],
    4: ["guest-laptop", "guest-phone", "guest-tablet"],
    5: ["sw-access", "ap-mgmt", "ups", "pdu", "camera"],
}


def _mac() -> str:
    """Generate a plausible-looking MAC from the OUI pool."""
    return "%s:%02x:%02x:%02x" % (RNG.choice(OUIS), RNG.randint(0, 255),
                                  RNG.randint(0, 255), RNG.randint(0, 255))


def _client_id(mac: str) -> str:
    """Kea writes client-id as the hwtype byte (01) followed by the MAC."""
    return "01:" + mac


def build_config4(target: str) -> dict:
    """Assemble the Dhcp4 config: global options/timers, shared networks,
    one standalone subnet, per-subnet options, and host reservations.

    lease-database and logger paths point into the sandbox rather than
    /var/lib/kea and /var/log/kea. The Logs viewer reads its path back out of
    this config (see routes/system.py _log_file_for_viewing), so pointing the
    logger at a system path the demo can't read would leave the Logs page
    permanently empty.
    """
    shared_networks: dict = {}
    standalone: list = []

    for spec in SUBNETS4:
        options = [
            {"name": "routers", "data": spec["gw"]},
            {"name": "domain-name-servers", "data": f"{DNS_PRIMARY}, {DNS_SECONDARY}"},
        ]
        # Guest wifi deliberately uses public resolvers and a short lease —
        # a realistic split that also shows per-subnet options overriding globals.
        if spec["id"] == 4:
            options[1] = {"name": "domain-name-servers", "data": "9.9.9.9, 149.112.112.112"}
        else:
            options.append({"name": "domain-name", "data": DOMAIN_NAME})
        # Voice VLAN carries the provisioning options a TR-069/SIP deployment needs.
        if spec["id"] == 3:
            options.append({"name": "tftp-server-name", "data": "10.20.30.5"})
            options.append({"name": "vendor-encapsulated-options", "data": ACS_URL})

        subnet_obj = {
            "id": spec["id"],
            "subnet": spec["cidr"],
            "pools": [{"pool": f"{spec['pool'][0]} - {spec['pool'][1]}"}],
            "option-data": options,
            "reservations": RESERVATIONS4.get(spec["id"], []),
        }
        if spec["id"] == 4:
            subnet_obj["valid-lifetime"] = 1800

        if spec["network"] is None:
            standalone.append(subnet_obj)
        else:
            shared_networks.setdefault(spec["network"], []).append(subnet_obj)

    return {
        "Dhcp4": {
            "interfaces-config": {"interfaces": []},
            "control-socket": {
                "socket-type": "unix",
                "socket-name": "/var/run/kea/kea-dhcp4-ctrl.sock",
            },
            "lease-database": {
                "type": "memfile",
                "lfc-interval": 3600,
                "name": os.path.join(target, "kea-leases4.csv"),
            },
            "host-reservation-identifiers": ["hw-address"],
            "valid-lifetime": 4000,
            "renew-timer": 1000,
            "rebind-timer": 2000,
            "option-data": [
                {"name": "domain-name-servers", "data": f"{DNS_PRIMARY}, {DNS_SECONDARY}"},
                {"name": "ntp-servers", "data": NTP_SERVER},
            ],
            "shared-networks": [
                {"name": name, "subnet4": subnets}
                for name, subnets in shared_networks.items()
            ],
            "subnet4": standalone,
            "loggers": [{
                "name": "kea-dhcp4",
                "output_options": [{
                    "output": os.path.join(target, "kea-dhcp4.log"),
                    "maxver": 8,
                    "maxsize": 204800,
                    "flush": True,
                }],
                "severity": "INFO",
                "debuglevel": 0,
            }],
        }
    }


def build_config6(target: str) -> dict:
    """Assemble the Dhcp6 config: shared networks with address pools, one
    prefix-delegation pool, per-subnet options, and DUID reservations.

    Sandbox lease/log paths, for the same reason as build_config4().
    """
    shared_networks: dict = {}

    for spec in SUBNETS6:
        options = [
            {"name": "dns-servers", "data": "2001:db8:10::10, 2001:db8:10::11"},
            {"name": "domain-search", "data": DOMAIN_NAME},
        ]
        subnet_obj = {
            "id": spec["id"],
            "subnet": spec["cidr"],
            "pools": [{"pool": f"{spec['pool'][0]} - {spec['pool'][1]}"}],
            "option-data": options,
            "reservations": RESERVATIONS6.get(spec["id"], []),
        }
        if "pd" in spec:
            prefix, delegated_len = spec["pd"]
            subnet_obj["pd-pools"] = [{"prefix": prefix, "delegated-len": delegated_len}]

        shared_networks.setdefault(spec["network"], []).append(subnet_obj)

    return {
        "Dhcp6": {
            "interfaces-config": {"interfaces": []},
            "control-socket": {
                "socket-type": "unix",
                "socket-name": "/var/run/kea/kea-dhcp6-ctrl.sock",
            },
            "lease-database": {
                "type": "memfile",
                "lfc-interval": 3600,
                "name": os.path.join(target, "kea-leases6.csv"),
            },
            "host-reservation-identifiers": ["duid"],
            "preferred-lifetime": 3000,
            "valid-lifetime": 4000,
            "renew-timer": 1000,
            "rebind-timer": 2000,
            "option-data": [
                {"name": "dns-servers", "data": "2001:db8:10::10, 2001:db8:10::11"},
            ],
            "shared-networks": [
                {"name": name, "subnet6": subnets}
                for name, subnets in shared_networks.items()
            ],
            "subnet6": [],
            "loggers": [{
                "name": "kea-dhcp6",
                "output_options": [{
                    "output": os.path.join(target, "kea-dhcp6.log"),
                    "maxver": 8,
                    "maxsize": 204800,
                    "flush": True,
                }],
                "severity": "INFO",
                "debuglevel": 0,
            }],
        }
    }


# Kea 2.x memfile lease4 schema.
LEASE4_COLUMNS = [
    "address", "hwaddr", "client_id", "valid_lifetime", "expire", "subnet_id",
    "fqdn_fwd", "fqdn_rev", "hostname", "state", "user_context", "pool_id",
]

# Kea 2.x memfile lease6 schema — note it differs from lease4's (duid instead
# of hwaddr, plus lease_type/iaid/prefix_len columns).
LEASE6_COLUMNS = [
    "address", "duid", "valid_lifetime", "expire", "subnet_id", "pref_lifetime",
    "lease_type", "iaid", "prefix_len", "fqdn_fwd", "fqdn_rev", "hostname",
    "hwaddr", "state", "user_context", "pool_id",
]


def build_leases4(now: int) -> list:
    """Generate active DHCPv4 leases spread across the pools.

    Expiry is staggered between ~10 minutes and ~4000 seconds out so the
    Leases page shows a realistic mix rather than one uniform timestamp, and
    so a demo reset always produces leases that are genuinely still active.
    """
    rows = []
    # Weight the busy corporate VLANs more heavily than mgmt/guest.
    weights = {1: 22, 2: 16, 3: 10, 4: 9, 5: 5}

    for spec in SUBNETS4:
        count = weights[spec["id"]]
        # Start each subnet's leases just past its pool start, leaving a gap so
        # the "available IPs" calculation still has room to show.
        pool_start_last_octet = int(spec["pool"][0].split(".")[-1])
        for i in range(count):
            last_octet = pool_start_last_octet + i
            address = f"{spec['net']}.{last_octet}"
            mac = _mac()
            valid_lifetime = 1800 if spec["id"] == 4 else 4000
            expire = now + RNG.randint(600, valid_lifetime)
            hostname = f"{RNG.choice(HOSTNAME_POOLS[spec['id']])}-{i + 1:02d}"
            rows.append({
                "address": address,
                "hwaddr": mac,
                "client_id": _client_id(mac),
                "valid_lifetime": valid_lifetime,
                "expire": expire,
                "subnet_id": spec["id"],
                "fqdn_fwd": 1,
                "fqdn_rev": 1,
                "hostname": hostname,
                "state": 0,
                "user_context": "",
                "pool_id": 0,
            })

    assert len(rows) == TARGET_ACTIVE_LEASES4, (
        f"expected {TARGET_ACTIVE_LEASES4} leases, built {len(rows)} — keep the "
        "demo under ez_kea.license.NAG_LEASE_THRESHOLD"
    )
    return rows


def build_leases6(now: int) -> list:
    """Generate active DHCPv6 leases: IA_NA addresses plus a few IA_PD
    delegated prefixes, so both lease types render in the Leases (IPv6) view."""
    rows = []
    counts = {1: 8, 2: 6, 3: 5, 4: 2}

    for spec in SUBNETS6:
        base = spec["pool"][0].rsplit(":", 1)[0]
        start = int(spec["pool"][0].rsplit(":", 1)[1], 16)
        for i in range(counts[spec["id"]]):
            address = f"{base}:{start + i:x}"
            mac = _mac()
            duid = "00:03:00:01:" + mac
            expire = now + RNG.randint(600, 4000)
            rows.append({
                "address": address,
                "duid": duid,
                "valid_lifetime": 4000,
                "expire": expire,
                "subnet_id": spec["id"],
                "pref_lifetime": 3000,
                "lease_type": 0,          # IA_NA
                "iaid": RNG.randint(1, 999999),
                "prefix_len": 128,
                "fqdn_fwd": 1,
                "fqdn_rev": 1,
                "hostname": f"{RNG.choice(HOSTNAME_POOLS[spec['id']])}-v6-{i + 1:02d}",
                "hwaddr": mac,
                "state": 0,
                "user_context": "",
                "pool_id": 0,
            })

    # Two delegated prefixes handed to branch CPE routers out of the PD pool.
    for i, prefix_base in enumerate(("2001:db8:4000:100::", "2001:db8:4000:200::")):
        mac = _mac()
        rows.append({
            "address": prefix_base,
            "duid": "00:03:00:01:" + mac,
            "valid_lifetime": 4000,
            "expire": now + RNG.randint(1200, 4000),
            "subnet_id": 4,
            "pref_lifetime": 3000,
            "lease_type": 2,              # IA_PD
            "iaid": RNG.randint(1, 999999),
            "prefix_len": 56,
            "fqdn_fwd": 0,
            "fqdn_rev": 0,
            "hostname": f"cpe-branch-office-{i + 1:02d}",
            "hwaddr": mac,
            "state": 0,
            "user_context": "",
            "pool_id": 0,
        })

    return rows


def build_log4(leases: list, now: int) -> str:
    """Render a plausible kea-dhcp4 log tail from the generated leases.

    Format matches Kea's own logger output so the Logs page's severity
    highlighting and its DHCP4_LEASE_ALLOC search example both work.
    """
    lines = []
    start = datetime.fromtimestamp(now) - timedelta(minutes=45)

    lines.append(_log_line(start, "INFO", "kea-dhcp4.dhcp4",
                           "DHCP4_STARTED Kea DHCPv4 server version 2.4.1 started"))
    lines.append(_log_line(start + timedelta(seconds=1), "INFO", "kea-dhcp4.dhcpsrv",
                           "DHCPSRV_MEMFILE_DB opening memory file lease database: "
                           "lfc-interval=3600 name=/var/lib/kea/kea-leases4.csv type=memfile"))

    offset = 5
    for lease in leases[:55]:
        stamp = start + timedelta(seconds=offset)
        tid = RNG.randint(0x10000000, 0xFFFFFFFF)
        lines.append(_log_line(
            stamp, "INFO", "kea-dhcp4.leases",
            f"DHCP4_LEASE_ALLOC [hwtype=1 {lease['hwaddr']}], cid=[{lease['client_id']}], "
            f"tid=0x{tid:x}: lease {lease['address']} has been allocated for "
            f"{lease['valid_lifetime']} seconds"
        ))
        offset += RNG.randint(3, 40)

    # A couple of realistic non-INFO events so the Logs page's colour coding
    # and severity filtering have something to show.
    lines.append(_log_line(start + timedelta(seconds=offset + 12), "WARN", "kea-dhcp4.dhcp4",
                           "DHCP4_PACKET_NAK_0001 [hwtype=1 3c:07:54:88:12:9a], cid=[no info], "
                           "tid=0x4a2b1c3d: failed to select a subnet for incoming packet, src "
                           "10.20.99.7, type DHCPREQUEST"))
    lines.append(_log_line(start + timedelta(seconds=offset + 48), "INFO", "kea-dhcp4.leases",
                           "DHCP4_LEASE_RENEW [hwtype=1 18:64:72:5d:0e:91], cid=[01:18:64:72:5d:0e:91], "
                           "tid=0x7b3e9f21: lease 10.20.20.31 has been renewed for 4000 seconds"))
    return "\n".join(lines) + "\n"


def build_log6(leases: list, now: int) -> str:
    """Render a plausible kea-dhcp6 log tail from the generated v6 leases."""
    lines = []
    start = datetime.fromtimestamp(now) - timedelta(minutes=40)

    lines.append(_log_line(start, "INFO", "kea-dhcp6.dhcp6",
                           "DHCP6_STARTED Kea DHCPv6 server version 2.4.1 started"))

    offset = 4
    for lease in leases:
        stamp = start + timedelta(seconds=offset)
        tid = RNG.randint(0x100000, 0xFFFFFF)
        if lease["lease_type"] == 2:
            lines.append(_log_line(
                stamp, "INFO", "kea-dhcp6.leases",
                f"DHCP6_PD_LEASE_ALLOC duid=[{lease['duid']}], tid=0x{tid:x}, "
                f"iaid={lease['iaid']}: lease {lease['address']}/{lease['prefix_len']} "
                f"has been allocated for {lease['valid_lifetime']} seconds"
            ))
        else:
            lines.append(_log_line(
                stamp, "INFO", "kea-dhcp6.leases",
                f"DHCP6_LEASE_ALLOC duid=[{lease['duid']}], tid=0x{tid:x}, "
                f"iaid={lease['iaid']}: lease {lease['address']} has been allocated "
                f"for {lease['valid_lifetime']} seconds"
            ))
        offset += RNG.randint(5, 50)

    return "\n".join(lines) + "\n"


def build_log4_history_day(leases: list, day_start: datetime, count: int) -> str:
    """One day of plausible DHCPv4 traffic drawn from the demo's own devices.

    Reusing the same lease population as the live log is what makes the demo's
    log search worth trying: a MAC or IP copied off the Leases page has a month
    of history behind it rather than a single line.
    """
    lines = []
    for _ in range(count):
        lease = RNG.choice(leases)
        stamp = day_start + timedelta(seconds=RNG.randint(0, 86399))
        tid = RNG.randint(0x10000000, 0xFFFFFFFF)
        roll = RNG.random()
        if roll < 0.45:
            lines.append(_log_line(
                stamp, "INFO", "kea-dhcp4.leases",
                f"DHCP4_LEASE_ALLOC [hwtype=1 {lease['hwaddr']}], cid=[{lease['client_id']}], "
                f"tid=0x{tid:x}: lease {lease['address']} has been allocated for "
                f"{lease['valid_lifetime']} seconds"
            ))
        elif roll < 0.85:
            lines.append(_log_line(
                stamp, "INFO", "kea-dhcp4.leases",
                f"DHCP4_LEASE_RENEW [hwtype=1 {lease['hwaddr']}], cid=[{lease['client_id']}], "
                f"tid=0x{tid:x}: lease {lease['address']} has been renewed for "
                f"{lease['valid_lifetime']} seconds"
            ))
        elif roll < 0.95:
            lines.append(_log_line(
                stamp, "INFO", "kea-dhcp4.leases",
                f"DHCP4_RELEASE [hwtype=1 {lease['hwaddr']}], cid=[{lease['client_id']}], "
                f"tid=0x{tid:x}: address {lease['address']} has been released"
            ))
        else:
            lines.append(_log_line(
                stamp, "WARN", "kea-dhcp4.dhcp4",
                f"DHCP4_PACKET_NAK_0001 [hwtype=1 {lease['hwaddr']}], cid=[no info], "
                f"tid=0x{tid:x}: failed to select a subnet for incoming packet, src "
                f"{lease['address']}, type DHCPREQUEST"
            ))

    # The timestamp prefix is fixed-width, so a plain sort puts the day in
    # chronological order.
    lines.sort()
    return "\n".join(lines) + "\n"


def build_log6_history_day(leases: list, day_start: datetime, count: int) -> str:
    """One day of plausible DHCPv6 traffic, mirroring build_log4_history_day."""
    lines = []
    for _ in range(count):
        lease = RNG.choice(leases)
        stamp = day_start + timedelta(seconds=RNG.randint(0, 86399))
        tid = RNG.randint(0x100000, 0xFFFFFF)
        verb = "DHCP6_PD_LEASE_ALLOC" if lease["lease_type"] == 2 else "DHCP6_LEASE_ALLOC"
        suffix = f"/{lease['prefix_len']}" if lease["lease_type"] == 2 else ""
        lines.append(_log_line(
            stamp, "INFO", "kea-dhcp6.leases",
            f"{verb} duid=[{lease['duid']}], tid=0x{tid:x}, iaid={lease['iaid']}: "
            f"lease {lease['address']}{suffix} has been allocated for "
            f"{lease['valid_lifetime']} seconds"
        ))
    lines.sort()
    return "\n".join(lines) + "\n"


def write_log_history(target: str, filename: str, day_texts: list) -> None:
    """Write the live log plus rotated siblings, the way logrotate leaves them.

    `day_texts[0]` is today's live file; index 1 becomes `.1` uncompressed and
    everything older becomes `.N.gz`, which is the standard `delaycompress`
    layout and gives the log index's archive backfill something real to chew on.
    """
    # Clear siblings from an earlier seed first, or shortening the history
    # would leave orphaned archives behind to be indexed forever.
    for stale in glob.glob(os.path.join(target, filename + ".*")):
        os.remove(stale)

    for age, text in enumerate(day_texts):
        if age == 0:
            path = os.path.join(target, filename)
        elif age == 1:
            path = os.path.join(target, f"{filename}.1")
        else:
            path = os.path.join(target, f"{filename}.{age}.gz")

        if path.endswith(".gz"):
            with gzip.open(path, "wt") as handle:
                handle.write(text)
        else:
            with open(path, "w") as handle:
                handle.write(text)


def _log_line(stamp: datetime, severity: str, logger: str, message: str) -> str:
    """Format a single Kea-style log line."""
    ms = RNG.randint(0, 999)
    pid = 1284
    thread = RNG.randint(140000000000, 140999999999)
    return (f"{stamp.strftime('%Y-%m-%d %H:%M:%S')}.{ms:03d} {severity:5s} "
            f"[{logger}/{pid}.{thread}] {message}")


def write_csv(path: str, columns: list, rows: list) -> None:
    """Write a Kea-style lease CSV with its header row."""
    with open(path, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def seed_database(db_path: str, username: str, password: str, is_admin: bool) -> None:
    """Recreate the EZ-Kea database with a single, known demo account.

    Deliberately rebuilt from empty on every run: a visitor who changes the
    demo password (Profile > Change Password is open to any logged-in user)
    would otherwise lock everyone else out until the next manual fix.

    The account is non-admin by default, so the User Management, Licensing,
    and Email Settings pages stay out of reach of the public — a visitor
    cannot enter a bogus license key or point SMTP at a mail server they
    control. Pass --admin-demo-user to override for a private walkthrough.
    """
    from flask import Flask
    from werkzeug.security import generate_password_hash
    from ez_kea import db
    from ez_kea.models import User

    if os.path.exists(db_path):
        os.remove(db_path)

    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.abspath(db_path)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)

    with app.app_context():
        db.create_all()
        db.session.add(User(
            username=username,
            name="Demo User",
            password_hash=generate_password_hash(password),
            email="",
            is_admin=is_admin,
            # No forced credential change: the demo account's whole purpose is
            # to log straight in with the published password. Leaving
            # must_change_password set would dump every visitor into the
            # account-setup wizard instead of the dashboard.
            must_change_password=False,
            must_change_username=False,
            # Not break-glass: that flag marks an account undeletable, which
            # only matters for a real install's recovery login.
            is_break_glass=False,
        ))
        db.session.commit()


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed the EZ-Kea public demo data set.")
    parser.add_argument("--target", default="./data",
                        help="Data directory to write into (default: ./data)")
    parser.add_argument("--demo-user", default=DEFAULT_DEMO_USERNAME,
                        help=f"Demo account username (default: {DEFAULT_DEMO_USERNAME})")
    parser.add_argument("--demo-password", default=DEFAULT_DEMO_PASSWORD,
                        help=f"Demo account password (default: {DEFAULT_DEMO_PASSWORD})")
    parser.add_argument("--admin-demo-user", action="store_true",
                        help="Make the demo account an admin (exposes user/licensing/SMTP pages)")
    parser.add_argument("--skip-db", action="store_true",
                        help="Only rewrite config/leases/logs, leave the database untouched")
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    os.makedirs(target, exist_ok=True)
    os.makedirs(os.path.join(target, "backups"), exist_ok=True)

    now = int(datetime.now().timestamp())

    config4_path = os.path.join(target, "kea-dhcp4.conf")
    config6_path = os.path.join(target, "kea-dhcp6.conf")
    with open(config4_path, "w") as handle:
        json.dump(build_config4(target), handle, indent=2)
    with open(config6_path, "w") as handle:
        json.dump(build_config6(target), handle, indent=2)

    leases4 = build_leases4(now)
    leases6 = build_leases6(now)
    write_csv(os.path.join(target, "kea-leases4.csv"), LEASE4_COLUMNS, leases4)
    write_csv(os.path.join(target, "kea-leases6.csv"), LEASE6_COLUMNS, leases6)

    # Today's live log, then one file per older day. build_log4/6 still render
    # the recent tail the Logs page opens on; the older days exist so the log
    # search has a month of history to actually search.
    midnight = datetime.fromtimestamp(now).replace(hour=0, minute=0, second=0, microsecond=0)
    write_log_history(target, "kea-dhcp4.log", [build_log4(leases4, now)] + [
        build_log4_history_day(leases4, midnight - timedelta(days=day), LOG_LINES_PER_HISTORY_DAY)
        for day in range(1, LOG_HISTORY_DAYS)
    ])
    write_log_history(target, "kea-dhcp6.log", [build_log6(leases6, now)] + [
        build_log6_history_day(leases6, midnight - timedelta(days=day), LOG_LINES_PER_HISTORY_DAY // 4)
        for day in range(1, LOG_HISTORY_DAYS)
    ])

    # Pin EZ-Kea to this sandbox so the demo can never be re-pointed at a real
    # /etc/kea config by the auto-discovery pass on the next restart.
    settings = {
        "dhcp_config_file": config4_path,
        "dhcp_leases_file": os.path.join(target, "kea-leases4.csv"),
        "dhcp_log_file":    os.path.join(target, "kea-dhcp4.log"),
        "dhcp6_config_file": config6_path,
        "dhcp6_leases_file": os.path.join(target, "kea-leases6.csv"),
        "dhcp6_log_file":    os.path.join(target, "kea-dhcp6.log"),
        "kea_dhcp4_cmd": "kea-dhcp4",
        "kea_dhcp6_cmd": "kea-dhcp6",
        "kea_ctrl_cmd": "keactrl",
    }
    with open(os.path.join(target, "ez-kea-settings.json"), "w") as handle:
        json.dump(settings, handle, indent=2)

    if not args.skip_db:
        seed_database(os.path.join(target, "ez-kea.db"),
                      args.demo_user, args.demo_password, args.admin_demo_user)

    print(f"Seeded demo data into {target}")
    print(f"  DHCPv4: {len(leases4)} active leases across {len(SUBNETS4)} subnets")
    print(f"  DHCPv6: {len(leases6)} active leases across {len(SUBNETS6)} subnets")
    if not args.skip_db:
        role = "admin" if args.admin_demo_user else "standard user"
        print(f"  Account: {args.demo_user} / {args.demo_password} ({role})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
