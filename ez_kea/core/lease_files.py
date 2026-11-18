# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
ez_kea/core/lease_files.py

Kea's memfile lease store is not one file. When lease file cleanup (LFC,
`lfc-interval`) runs, Kea moves the live file aside to `<file>.1`, starts a
fresh `<file>` holding only the CSV header, and the LFC process compacts
`<file>.2` + `<file>.1` into `<file>.output`, then `.completed`, then renames
that to `<file>.2`. So right after an LFC pass nearly every current lease is
in `<file>.2` and the main file is empty, and reading only the main file
shows almost no leases until clients renew.

Kea itself rebuilds its lease table at startup by loading, in order,
`<file>.completed` (if an LFC finished but did not get to rotate), otherwise
`<file>.2` then `<file>.1`, and finally `<file>`, with later rows replacing
earlier ones for the same address. Everything here reads the same set in the
same order.
"""
import csv
import os
from typing import Dict, Iterator, List


def lease_file_set(path: str) -> List[str]:
    """The files that make up the lease store at `path`, oldest first, in the
    order Kea loads them. Missing files are left out."""
    if not path:
        return []
    if os.path.exists(path + ".completed"):
        candidates = [path + ".completed", path]
    else:
        candidates = [path + ".2", path + ".1", path]
    return [p for p in candidates if os.path.isfile(p)]


def iter_lease_rows(path: str) -> Iterator[Dict[str, str]]:
    """Every CSV row across the lease store, oldest first. A later row for
    the same address supersedes an earlier one, so callers should keep the
    last occurrence. A file that vanishes mid-read (LFC rotating it) is
    skipped; its rows are in the next file of the set by then."""
    for file_path in lease_file_set(path):
        try:
            with open(file_path, "r", newline="") as handle:
                for row in csv.DictReader(handle):
                    yield row
        except FileNotFoundError:
            continue


def fingerprint(path: str) -> str:
    """A cheap "has the lease store changed" signal covering every file in
    the set, so an LFC rotation (which can leave the main file's size and
    mtime looking unchanged) still triggers a reparse."""
    parts = []
    for suffix in (".completed", ".2", ".1", ""):
        try:
            stat = os.stat(path + suffix)
        except OSError:
            parts.append("-")
            continue
        parts.append(f"{stat.st_mtime_ns}:{stat.st_size}")
    return ",".join(parts)
