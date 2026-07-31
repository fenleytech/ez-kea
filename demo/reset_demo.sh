#!/usr/bin/env bash
#
# demo/reset_demo.sh — restore the public demo to its pristine seeded state.
#
# Run on a timer (see demo/systemd/ez-kea-demo-reset.timer). Anyone who logs
# into the demo can create, edit, and delete configuration — EZ-Kea has no
# read-only role — so the demo is expected to drift and is simply rebuilt.
#
# The app service is restarted after reseeding rather than left running:
# seed_demo.py replaces data/ez-kea.db outright, and a live process holding
# pooled SQLite connections would keep talking to the deleted inode.
#
# Usage:
#   demo/reset_demo.sh                      # uses the defaults below
#   DEMO_ROOT=/opt/ez-kea demo/reset_demo.sh
set -euo pipefail

DEMO_ROOT="${DEMO_ROOT:-/srv/ez-kea-demo}"
DEMO_DATA="${DEMO_DATA:-$DEMO_ROOT/data}"
DEMO_PYTHON="${DEMO_PYTHON:-$DEMO_ROOT/venv/bin/python}"
DEMO_SERVICE="${DEMO_SERVICE:-ez-kea-demo.service}"
DEMO_USER="${DEMO_USER:-demo}"
DEMO_PASSWORD="${DEMO_PASSWORD:-demo}"

if [[ ! -x "$DEMO_PYTHON" ]]; then
    echo "reset_demo: no interpreter at $DEMO_PYTHON" >&2
    exit 1
fi

"$DEMO_PYTHON" "$DEMO_ROOT/demo/seed_demo.py" \
    --target "$DEMO_DATA" \
    --demo-user "$DEMO_USER" \
    --demo-password "$DEMO_PASSWORD"

# Clear any backups a visitor created, so the Restore dialog doesn't slowly
# accumulate hundreds of entries between deploys.
if [[ -d "$DEMO_DATA/backups" ]]; then
    find "$DEMO_DATA/backups" -type f -delete
fi

# Drop the log search index. seed_demo.py rewrites the whole log history on
# every reset, so a kept index would stack each reset's copy on top of the last
# and the demo's "lines indexed" figure would climb forever. The background
# indexer rebuilds it from the freshly seeded files within a minute of restart.
rm -f "$DEMO_DATA"/ez-kea-logindex.db "$DEMO_DATA"/ez-kea-logindex.db-wal \
      "$DEMO_DATA"/ez-kea-logindex.db-shm

# Only restart if we're running under systemd with the unit installed; this
# lets the script also be run by hand during setup.
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files "$DEMO_SERVICE" >/dev/null 2>&1; then
    systemctl restart "$DEMO_SERVICE"
    echo "reset_demo: reseeded $DEMO_DATA and restarted $DEMO_SERVICE"
else
    echo "reset_demo: reseeded $DEMO_DATA (no systemd restart performed)"
fi
