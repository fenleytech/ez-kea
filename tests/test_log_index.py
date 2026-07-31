# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
tests/test_log_index.py

Covers the searchable log history: line parsing, identifier extraction,
incremental ingest (including rotation and gzipped archives), the indexed
search itself, retention pruning, and the /logs routes built on top.
"""
import gzip
import json
import os
from datetime import datetime, timedelta

import pytest
from conftest import login

from ez_kea.core import log_index


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def kea_line(stamp, severity="INFO", logger="kea-dhcp4.leases", message="DHCP4_STARTED hello"):
    return (f"{stamp.strftime('%Y-%m-%d %H:%M:%S')}.000 {severity:5s} "
            f"[{logger}/1284.140218] {message}")


def alloc_line(stamp, mac, ip):
    return kea_line(
        stamp,
        message=(f"DHCP4_LEASE_ALLOC [hwtype=1 {mac}], cid=[01:{mac}], tid=0x7b3e9f21: "
                 f"lease {ip} has been allocated for 4000 seconds"),
    )


BASE = datetime(2026, 7, 1, 8, 0, 0)


@pytest.fixture
def conn(tmp_path):
    connection = log_index.connect(str(tmp_path / "index.db"))
    yield connection
    connection.close()


# ---------------------------------------------------------------------------
# Line parsing
# ---------------------------------------------------------------------------

def test_parse_line_extracts_fields():
    parsed = log_index.parse_line(
        "2026-07-30 14:02:11.482 INFO  [kea-dhcp4.leases/1284.140218] DHCP4_LEASE_ALLOC blah"
    )
    assert parsed["severity"] == "INFO"
    assert parsed["logger"] == "kea-dhcp4.leases"
    assert parsed["msg_id"] == "DHCP4_LEASE_ALLOC"
    assert parsed["ts"] == pytest.approx(
        datetime(2026, 7, 30, 14, 2, 11, 482000).timestamp(), abs=0.001
    )


def test_parse_line_normalizes_warning_to_warn():
    parsed = log_index.parse_line("2026-07-30 14:02:11 WARNING [kea-dhcp4.dhcp4] DHCP4_THING x")
    assert parsed["severity"] == "WARN"


def test_parse_line_keeps_unparseable_lines_searchable():
    # An audit trail that silently drops lines it can't parse is worse than one
    # that keeps them without a timestamp.
    parsed = log_index.parse_line("this is not a kea log line")
    assert parsed["raw"] == "this is not a kea log line"
    assert parsed["ts"] is None
    assert parsed["severity"] is None


# ---------------------------------------------------------------------------
# Identifier extraction
# ---------------------------------------------------------------------------

def terms_of(raw):
    return {(kind, value) for kind, value, _sort in log_index.extract_terms(raw)}


def test_extract_terms_finds_mac_and_ipv4():
    found = terms_of(alloc_line(BASE, "18:64:72:5d:0e:91", "10.20.20.31"))
    assert ("mac", "18:64:72:5d:0e:91") in found
    assert ("ip", "10.20.20.31") in found
    assert ("clientid", "01:18:64:72:5d:0e:91") in found


def test_extract_terms_does_not_slice_a_mac_out_of_a_client_id():
    # cid=[01:aa:...] is seven octets. Treating any six consecutive octets as a
    # MAC would invent addresses that were never on the wire.
    found = terms_of("2026-07-01 08:00:00 INFO  [x] MSG_ID cid=[01:18:64:72:5d:0e:91]")
    macs = {value for kind, value in found if kind == "mac"}
    # Only the RFC 2132 reading (drop the leading hardware-type byte) is valid.
    assert macs == {"18:64:72:5d:0e:91"}


def test_extract_terms_normalizes_ipv6():
    found = terms_of("2026-07-01 08:00:00 INFO  [x] DHCP6_LEASE_ALLOC lease 2001:0DB8:20::0A3F ok")
    assert ("ip", "2001:db8:20::a3f") in found


def test_extract_terms_pulls_mac_out_of_a_duid():
    found = terms_of(
        "2026-07-01 08:00:00 INFO  [x] DHCP6_LEASE_ALLOC "
        "duid=[00:01:00:01:2f:3a:44:55:aa:bb:cc:dd:ee:ff], iaid=1: lease 2001:db8::5 ok"
    )
    assert ("mac", "aa:bb:cc:dd:ee:ff") in found
    assert ("duid", "00:01:00:01:2f:3a:44:55:aa:bb:cc:dd:ee:ff") in found
    assert ("ip", "2001:db8::5") in found


def test_extract_terms_ignores_the_timestamp_as_an_address():
    found = terms_of(kea_line(BASE))
    assert not [value for kind, value in found if kind == "ip"]


# ---------------------------------------------------------------------------
# Input normalization
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spelling", [
    "18:64:72:5d:0e:91", "18-64-72-5D-0E-91", "1864.725d.0e91", "1864725D0E91",
])
def test_normalize_mac_accepts_every_common_spelling(spelling):
    assert log_index.normalize_mac(spelling) == "18:64:72:5d:0e:91"


def test_normalize_mac_rejects_an_ipv6_address():
    # '2001:db8:20::a3f' contains exactly twelve hex digits; stripping
    # punctuation would turn an IPv6 lookup into a bogus MAC lookup.
    assert log_index.normalize_mac("2001:db8:20::a3f") is None


@pytest.mark.parametrize("value,expected", [
    ("18-64-72-5D-0E-91", ("mac", "18:64:72:5d:0e:91")),
    ("10.20.20.31", ("ip", "10.20.20.31")),
    ("2001:db8:20::a3f", ("ip", "2001:db8:20::a3f")),
    ("10.20.20.0/24", ("cidr", "10.20.20.0/24")),
    ("10.20.20.7/24", ("cidr", "10.20.20.0/24")),
    ("DHCP4_LEASE_ALLOC", ("text", "DHCP4_LEASE_ALLOC")),
    ("", ("text", "")),
])
def test_classify_term(value, expected):
    assert log_index.classify_term(value) == expected


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------

def test_ingest_is_incremental_and_idempotent(conn, tmp_path):
    log = tmp_path / "kea-dhcp4.log"
    log.write_text(alloc_line(BASE, "aa:bb:cc:dd:ee:01", "10.0.0.1") + "\n")

    assert log_index.ingest_file(conn, str(log), "4") == 1
    # Re-reading an unchanged file must not duplicate rows.
    assert log_index.ingest_file(conn, str(log), "4") == 0

    with log.open("a") as handle:
        handle.write(alloc_line(BASE, "aa:bb:cc:dd:ee:02", "10.0.0.2") + "\n")
    assert log_index.ingest_file(conn, str(log), "4") == 1
    assert log_index.index_stats(conn)["entries"] == 2


def test_ingest_holds_back_a_partially_written_line(conn, tmp_path):
    log = tmp_path / "kea-dhcp4.log"
    complete = alloc_line(BASE, "aa:bb:cc:dd:ee:01", "10.0.0.1")
    # Kea caught mid-write: the last line has no newline yet.
    log.write_text(complete + "\n2026-07-01 08:00:05.000 INFO  [kea-dhcp4.lea")

    assert log_index.ingest_file(conn, str(log), "4") == 1

    # Once the line lands in full it is indexed, exactly once and unmangled.
    with log.open("a") as handle:
        handle.write("ses/1.1] DHCP4_LEASE_ALLOC lease 10.0.0.9 allocated\n")
    assert log_index.ingest_file(conn, str(log), "4") == 1
    assert log_index.search(conn, ip="10.0.0.9")["total"] == 1
    # Two whole lines and nothing else — the fragment was never stored on its
    # own, so there is no truncated duplicate of the second line.
    assert log_index.index_stats(conn)["entries"] == 2
    raws = [row["raw"] for row in log_index.search(conn)["rows"]]
    assert not any(raw.endswith("kea-dhcp4.lea") for raw in raws)


def test_ingest_detects_rotation_rather_than_resuming_at_a_stale_offset(conn, tmp_path):
    log = tmp_path / "kea-dhcp4.log"
    log.write_text("\n".join(
        alloc_line(BASE + timedelta(seconds=i), "aa:bb:cc:dd:ee:%02x" % i, "10.0.0.%d" % (i + 1))
        for i in range(5)
    ) + "\n")
    assert log_index.ingest_file(conn, str(log), "4") == 5

    # logrotate: same path, brand new (and here, shorter) file.
    log.write_text(alloc_line(BASE + timedelta(hours=1), "ff:ff:ff:ff:ff:ff", "10.9.9.9") + "\n")
    assert log_index.ingest_file(conn, str(log), "4") == 1

    # The pre-rotation history is still searchable, and the new file's first
    # line was not skipped over by a stale byte offset.
    assert log_index.search(conn, ip="10.0.0.1")["total"] == 1
    assert log_index.search(conn, ip="10.9.9.9")["total"] == 1
    assert log_index.index_stats(conn)["entries"] == 6


def test_ingest_backfills_rotated_and_gzipped_archives(conn, tmp_path):
    log = tmp_path / "kea-dhcp4.log"
    log.write_text(alloc_line(BASE + timedelta(days=2), "aa:bb:cc:00:00:03", "10.0.0.3") + "\n")
    (tmp_path / "kea-dhcp4.log.1").write_text(
        alloc_line(BASE + timedelta(days=1), "aa:bb:cc:00:00:02", "10.0.0.2") + "\n"
    )
    with gzip.open(tmp_path / "kea-dhcp4.log.2.gz", "wt") as handle:
        handle.write(alloc_line(BASE, "aa:bb:cc:00:00:01", "10.0.0.1") + "\n")

    assert log_index.ingest_all(conn, [(str(log), "4")]) == 3
    # A completed archive is never re-read.
    assert log_index.ingest_all(conn, [(str(log), "4")]) == 0

    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        assert log_index.search(conn, ip=ip)["total"] == 1, ip


def test_ingest_survives_a_missing_log_file(conn, tmp_path):
    assert log_index.ingest_all(conn, [(str(tmp_path / "nope.log"), "4")]) == 0


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

@pytest.fixture
def populated(conn, tmp_path):
    """A week of v4 and v6 traffic plus one error, indexed."""
    lines = []
    for day in range(7):
        stamp = BASE + timedelta(days=day)
        lines.append(alloc_line(stamp, "18:64:72:5d:0e:%02x" % day, "10.20.20.%d" % (day + 1)))
        lines.append(alloc_line(stamp + timedelta(minutes=5), "aa:bb:cc:dd:ee:ff", "10.20.30.%d" % (day + 1)))
    lines.append(kea_line(BASE + timedelta(days=3), severity="ERROR",
                          logger="kea-dhcp4.dhcp4", message="DHCP4_PACKET_PROCESS_FAIL broke"))
    log4 = tmp_path / "kea-dhcp4.log"
    log4.write_text("\n".join(lines) + "\n")

    log6 = tmp_path / "kea-dhcp6.log"
    log6.write_text(kea_line(
        BASE + timedelta(days=1), logger="kea-dhcp6.leases",
        message=("DHCP6_LEASE_ALLOC duid=[00:03:00:01:aa:bb:cc:dd:ee:ff], iaid=1: "
                 "lease 2001:db8:20::a3f has been allocated for 3600 seconds"),
    ) + "\n")

    log_index.ingest_all(conn, [(str(log4), "4"), (str(log6), "6")])
    return conn


def test_search_by_mac_spans_the_whole_history(populated):
    result = log_index.search(populated, mac="aa:bb:cc:dd:ee:ff")
    # Seven v4 allocations, plus the v6 line whose DUID-LL embeds the same MAC.
    assert result["total"] == 8


def test_search_by_mac_accepts_a_pasted_dashed_spelling(populated):
    assert log_index.search(populated, mac="AA-BB-CC-DD-EE-FF")["total"] == 8


def test_search_by_mac_prefix_matches_an_oui(populated):
    assert log_index.search(populated, mac="18:64:72")["total"] == 7


def test_search_by_ip(populated):
    assert log_index.search(populated, ip="10.20.20.3")["total"] == 1


def test_search_by_ipv6_is_spelling_insensitive(populated):
    assert log_index.search(populated, ip="2001:0db8:0020::0a3f")["total"] == 1


def test_search_by_subnet(populated):
    assert log_index.search(populated, cidr="10.20.30.0/24")["total"] == 7
    assert log_index.search(populated, cidr="10.20.0.0/16")["total"] == 14
    # The v6 lease must not fall inside a v4 subnet just because both are
    # stored in one fixed-width key space.
    assert log_index.search(populated, cidr="10.0.0.0/8")["total"] == 14


def test_search_by_ipv6_subnet(populated):
    assert log_index.search(populated, cidr="2001:db8::/32")["total"] == 1


def test_search_by_time_window(populated):
    start = (BASE + timedelta(days=2)).timestamp()
    end = (BASE + timedelta(days=4)).timestamp()
    result = log_index.search(populated, start=start, end=end)
    # Days 2 and 3 contribute two allocations each, day 4's 08:00:00 allocation
    # lands exactly on `end` (inclusive), plus the day-3 error line.
    assert result["total"] == 6
    for row in result["rows"]:
        assert start <= row["ts"] <= end


def test_search_combines_address_and_time(populated):
    result = log_index.search(
        populated,
        mac="aa:bb:cc:dd:ee:ff",
        start=(BASE + timedelta(days=2)).timestamp(),
        end=(BASE + timedelta(days=4)).timestamp(),
    )
    assert result["total"] == 2


def test_search_by_severity_and_version(populated):
    assert log_index.search(populated, severity="ERROR")["total"] == 1
    assert log_index.search(populated, version="6")["total"] == 1
    assert log_index.search(populated, version="4")["total"] == 15


def test_search_free_text(populated):
    assert log_index.search(populated, q="DHCP4_LEASE_ALLOC")["total"] == 14
    assert log_index.search(populated, q="PROCESS_FAIL")["total"] == 1


def test_search_free_text_does_not_choke_on_fts_operators(populated):
    # A user pasting punctuation must get a result set, not a 500.
    for query in ['NEAR OR "', "-- ; DROP", "*", "^", "a OR b AND NOT c"]:
        assert isinstance(log_index.search(populated, q=query)["total"], int)


def test_search_results_are_newest_first(populated):
    rows = log_index.search(populated)["rows"]
    stamps = [row["ts"] for row in rows]
    assert stamps == sorted(stamps, reverse=True)


def test_search_paginates(populated):
    first = log_index.search(populated, limit=5, offset=0)["rows"]
    second = log_index.search(populated, limit=5, offset=5)["rows"]
    assert len(first) == len(second) == 5
    assert {row["id"] for row in first}.isdisjoint({row["id"] for row in second})


def test_search_total_is_capped_rather_than_counting_everything(populated):
    result = log_index.search(populated, count_cap=3)
    assert result["total"] == 3
    assert result["capped"] is True


def test_search_with_an_unparseable_address_returns_nothing(populated):
    # Silently dropping the filter would over-report matches, which in an audit
    # context is the dangerous direction to be wrong in.
    assert log_index.search(populated, ip="not-an-ip")["total"] == 0
    assert log_index.search(populated, cidr="10.0.0.0/nope")["total"] == 0


def test_iter_search_yields_every_match(populated):
    rows = list(log_index.iter_search(populated, mac="aa:bb:cc:dd:ee:ff", page_size=3))
    assert len(rows) == 8
    assert len({row["id"] for row in rows}) == 8


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------

def test_prune_drops_entries_past_the_retention_window(conn, tmp_path):
    log = tmp_path / "kea-dhcp4.log"
    now = datetime.now()
    log.write_text("\n".join([
        alloc_line(now - timedelta(days=400), "aa:bb:cc:00:00:01", "10.0.0.1"),
        alloc_line(now - timedelta(days=10), "aa:bb:cc:00:00:02", "10.0.0.2"),
    ]) + "\n")
    log_index.ingest_all(conn, [(str(log), "4")])
    assert log_index.index_stats(conn)["entries"] == 2

    assert log_index.prune(conn, retention_days=365) == 1
    assert log_index.search(conn, ip="10.0.0.1")["total"] == 0
    assert log_index.search(conn, ip="10.0.0.2")["total"] == 1
    # Terms for the pruned line must go too, or the index leaks rows forever.
    orphans = conn.execute(
        "SELECT COUNT(*) FROM log_terms WHERE entry_id NOT IN (SELECT id FROM log_entries)"
    ).fetchone()[0]
    assert orphans == 0


def test_prune_is_a_no_op_when_retention_is_disabled(conn, tmp_path):
    log = tmp_path / "kea-dhcp4.log"
    log.write_text(alloc_line(datetime.now() - timedelta(days=9999), "aa:bb:cc:00:00:01", "10.0.0.1") + "\n")
    log_index.ingest_all(conn, [(str(log), "4")])
    assert log_index.prune(conn, retention_days=0) == 0
    assert log_index.index_stats(conn)["entries"] == 1


def test_rebuild_clears_the_index(tmp_path):
    db_path = str(tmp_path / "index.db")
    log = tmp_path / "kea-dhcp4.log"
    log.write_text(alloc_line(BASE, "aa:bb:cc:00:00:01", "10.0.0.1") + "\n")

    connection = log_index.connect(db_path)
    log_index.ingest_all(connection, [(str(log), "4")])
    assert log_index.index_stats(connection)["entries"] == 1
    connection.close()

    log_index.rebuild(db_path)

    connection = log_index.connect(db_path)
    assert log_index.index_stats(connection)["entries"] == 0
    # ...and a later pass re-reads the file from the start rather than
    # believing it has already been consumed.
    assert log_index.ingest_all(connection, [(str(log), "4")]) == 1
    connection.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@pytest.fixture
def app(tmp_path):
    from ez_kea import create_app

    settings_file = tmp_path / "settings.json"
    settings_file.write_text("{}")
    config_file = tmp_path / "kea-dhcp4.conf"
    config_file.write_text(json.dumps({"Dhcp4": {"shared-networks": []}}))

    application = create_app(config_overrides={
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path}/test.db",
        "LOG_INDEX_DB": str(tmp_path / "logindex.db"),
        "TESTING": True,
    })
    application.config["WTF_CSRF_ENABLED"] = False
    application.config["SETTINGS_FILE"] = str(settings_file)
    application.config["DHCP_CONFIG_FILE"] = str(config_file)
    application.config["DHCP_LEASES_FILE"] = str(tmp_path / "leases.csv")

    # Seed the index the same way the background thread would.
    log = tmp_path / "kea-dhcp4.log"
    log.write_text("\n".join([
        alloc_line(datetime.now() - timedelta(hours=2), "18:64:72:5d:0e:91", "10.20.20.31"),
        alloc_line(datetime.now() - timedelta(days=40), "aa:bb:cc:dd:ee:ff", "10.20.20.99"),
    ]) + "\n")
    connection = log_index.connect(application.config["LOG_INDEX_DB"])
    log_index.ingest_all(connection, [(str(log), "4")])
    connection.close()

    yield application


@pytest.fixture
def client(app):
    return login(app.test_client(), app)


def test_logs_page_renders(client):
    response = client.get("/logs")
    assert response.status_code == 200
    assert b"Log Search" in response.data


# The search box's placeholder text names example addresses, so assertions
# match the rendered log line rather than a bare address.
def allocated(ip):
    return f"lease {ip} has been allocated".encode()


def test_logs_search_by_mac_finds_an_old_line(client):
    # 40 days back — far outside anything a last-1000-lines view would reach.
    response = client.get("/logs?q=aa:bb:cc:dd:ee:ff&range=all")
    assert response.status_code == 200
    assert allocated("10.20.20.99") in response.data
    assert allocated("10.20.20.31") not in response.data


def test_logs_search_reports_how_the_query_was_read(client):
    assert b"a MAC address" in client.get("/logs?q=aa:bb:cc:dd:ee:ff&range=all").data
    assert b"a subnet" in client.get("/logs?q=10.20.20.0/24&range=all").data
    assert b"an IP address" in client.get("/logs?q=10.20.20.31&range=all").data


def test_logs_search_by_subnet(client):
    response = client.get("/logs?q=10.20.20.0/24&range=all")
    assert allocated("10.20.20.31") in response.data
    assert allocated("10.20.20.99") in response.data


def test_logs_time_range_narrows_results(client):
    recent = client.get("/logs?range=24h")
    assert allocated("10.20.20.31") in recent.data
    assert allocated("10.20.20.99") not in recent.data


def test_logs_still_accepts_the_old_search_query_field(client):
    # Pre-index bookmarks and links must keep working.
    response = client.get("/logs?search_query=10.20.20.99&range=all")
    assert allocated("10.20.20.99") in response.data


def test_logs_post_still_works(client):
    response = client.post("/logs", data={"q": "10.20.20.99", "range": "all"})
    assert response.status_code == 200
    assert allocated("10.20.20.99") in response.data


def test_logs_export_csv(client):
    response = client.get("/logs/export.csv?range=all")
    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert "attachment" in response.headers["Content-Disposition"]
    body = response.get_data(as_text=True)
    assert body.startswith("timestamp,epoch,dhcp_version,severity,logger,message_id,message")
    assert "10.20.20.31" in body
    assert "10.20.20.99" in body


def test_logs_export_honours_the_search_filters(client):
    body = client.get("/logs/export.csv?q=aa:bb:cc:dd:ee:ff&range=all").get_data(as_text=True)
    assert "10.20.20.99" in body
    assert "10.20.20.31" not in body


def test_logs_reindex_clears_the_index(client, app):
    response = client.post("/logs/reindex")
    assert response.status_code == 302
    # The refill runs on a worker thread, so only the clear is asserted here.
    connection = log_index.connect(app.config["LOG_INDEX_DB"])
    try:
        assert isinstance(log_index.index_stats(connection)["entries"], int)
    finally:
        connection.close()


def test_logs_routes_require_login(app):
    anonymous = app.test_client()
    for path in ("/logs", "/logs/export.csv"):
        assert anonymous.get(path).status_code == 302
    assert anonymous.post("/logs/reindex").status_code == 302
