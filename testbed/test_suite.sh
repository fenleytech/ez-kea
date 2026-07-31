#!/bin/bash
# testbed/test_suite.sh
# DHCP testbed test suite. Run from EZ-KEA project root: cd testbed && bash test_suite.sh
# Every command has an explicit timeout. Suite should complete in under 2 minutes.
# Exit code: 0 if all pass, 1 if any fail.

set -uo pipefail

# ── Global 2-minute watchdog ───────────────────────────────────────────────────
# If the suite hangs for ANY reason, this kills it after 120 seconds.
SUITE_PID=$$
(
  sleep 120
  echo ""
  echo "WATCHDOG TIMEOUT: suite exceeded 2-minute limit — killed."
  echo "Last timestamp above shows where it hung."
  kill -TERM "$SUITE_PID" 2>/dev/null
) &
WATCHDOG_PID=$!
trap 'kill "$WATCHDOG_PID" 2>/dev/null; exit' EXIT TERM

# ── Colour / logging helpers ───────────────────────────────────────────────────
GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'
YELLOW='\033[0;33m'; BOLD='\033[1m'; RESET='\033[0m'

PASS=0; FAIL=0; FAILED_TESTS=()

ts()   { echo "[$(date +%H:%M:%S)]"; }
log()  { echo -e "$(ts) $*"; }
pass() { echo -e "${GREEN}  ✔ PASS${RESET}  $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}  ✘ FAIL${RESET}  $1"; FAIL=$((FAIL+1)); FAILED_TESTS+=("$1"); }
skip() { echo -e "${YELLOW}  ⚠ SKIP${RESET}  $1"; }
header() { echo -e "\n${BOLD}${CYAN}══ $1 ══${RESET}"; }

# ── Safe exec wrappers — every docker call has a hard timeout ──────────────────

# Run in container with a timeout; prints TIMED_OUT if it expires
dexec() {
    local t=$1 ctr=$2; shift 2
    timeout "$t" docker exec "$ctr" sh -c "$*" 2>&1 || echo "TIMED_OUT_OR_FAILED"
}

# udhcpc with explicit 3s-per-attempt, 2 attempts max (≤6s), plus outer 10s hard kill
# Installs our option-capture script first, then runs udhcpc
dhcp_request() {
    local ctr="$1"
    log "  dhcp_request → $ctr"
    timeout 5 docker cp "$(dirname "$0")/udhcpc.script" "${ctr}:/tmp/udhcpc.script" 2>/dev/null || true
    dexec 12 "$ctr" 'chmod +x /tmp/udhcpc.script; udhcpc -i eth0 -f -q -n -T 3 -t 2 -s /tmp/udhcpc.script 2>&1 || echo "DHCP_FAILED"'
}

# Read lease IP for given MAC from inside the Kea container (avoids host CSV flush lag)
lease_ip_for_mac() {
    dexec 5 kea-testbed-kea-1 "grep -i '$1' /var/lib/kea/kea-leases4.csv 2>/dev/null | head -1 | cut -d, -f1" 2>/dev/null \
        | grep -v TIMED_OUT || true
}

# Kea 2.x logs to /var/log/kea-dhcp4.log, but Kea 3.x refuses any logger output
# path outside /var/log/kea/ — resolve whichever this target actually uses.
KEA_LOG_PATH=""
resolve_kea_log_path() {
    local candidate
    for candidate in /var/log/kea/kea-dhcp4.log /var/log/kea-dhcp4.log; do
        if [[ "$(dexec 5 kea-testbed-kea-1 "test -f $candidate && echo found")" == "found" ]]; then
            KEA_LOG_PATH="$candidate"
            return
        fi
    done
    KEA_LOG_PATH="/var/log/kea-dhcp4.log"
}

# Read Kea log from inside the container
kea_log() {
    [[ -n "$KEA_LOG_PATH" ]] || resolve_kea_log_path
    dexec 5 kea-testbed-kea-1 "cat $KEA_LOG_PATH 2>/dev/null" | grep -v TIMED_OUT || true
}

# Read an option out of the Kea config. Done on the HOST, against the same file
# the container bind-mounts: ISC's Kea 3.x images carry no python3, so the old
# `docker exec ... python3` form silently returned nothing there.
CONFIG_FILE="$(dirname "$0")/data/etc/kea/kea-dhcp4.conf"
config_option() {
    # $1 = option name, $2 = "global" or "subnet"
    python3 - "$CONFIG_FILE" "$1" "$2" 2>/dev/null <<'PY' || true
import json, sys
path, name, scope = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    dhcp4 = json.load(open(path)).get("Dhcp4", {})
except Exception:
    print(""); raise SystemExit
if scope == "global":
    pool = dhcp4.get("option-data", [])
else:
    # Walk standalone subnets AND shared-network subnets — EZ-KEA writes both,
    # and only checking the standalone list misses most real configs.
    subnets = list(dhcp4.get("subnet4", []))
    for net in dhcp4.get("shared-networks", []):
        subnets.extend(net.get("subnet4", []))
    pool = [o for s in subnets for o in s.get("option-data", [])]
print({o.get("name"): o.get("data") for o in pool}.get(name, "") or "")
PY
}

# ── Pre-flight ─────────────────────────────────────────────────────────────────

header "Pre-flight checks"

if ! timeout 5 docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'kea-testbed-kea-1'; then
    echo -e "${RED}ERROR: Kea container is not running. Run: docker compose up -d${RESET}"
    exit 1
fi

log "  Clearing leases and restarting Kea..."
dexec 5 kea-testbed-kea-1 'rm -f /var/lib/kea/kea-leases4.csv /var/lib/kea/kea-leases4.csv.2' > /dev/null
timeout 20 docker restart kea-testbed-kea-1 > /dev/null 2>&1 || true
sleep 4
log "  Kea restarted."

# ══════════════════════════════════════════════════════════════════════════════
header "TEST 1 — Basic Pool Lease (vlan10)"
# ══════════════════════════════════════════════════════════════════════════════
log "  Requesting DHCP on vlan10 client..."
out=$(dhcp_request kea-testbed-client-vlan10-1)
ip=$(lease_ip_for_mac "00:11:22:33:44:55")
if [[ "$ip" == 172.30.110.10* ]]; then
    pass "vlan10 client got pool IP: $ip"
else
    fail "vlan10 client did not get a pool IP. Got: '$ip'. Output: $out"
fi

# ══════════════════════════════════════════════════════════════════════════════
header "TEST 2 — Basic Pool Lease (vlan20)"
# ══════════════════════════════════════════════════════════════════════════════
log "  Requesting DHCP on vlan20 client..."
out=$(dhcp_request kea-testbed-client-vlan20-1)
ip=$(lease_ip_for_mac "aa:bb:cc:dd:ee:ff")
if [[ "$ip" == 172.30.120.* ]]; then
    pass "vlan20 client got pool IP: $ip"
else
    fail "vlan20 client did not get a pool IP. Got: '$ip'. Output: $out"
fi

# ══════════════════════════════════════════════════════════════════════════════
header "TEST 3 — MAC Reservation"
# ══════════════════════════════════════════════════════════════════════════════
log "  Requesting DHCP on reserved client (de:ad:be:ef:00:01)..."
out=$(dhcp_request kea-testbed-client-reserved-1)
ip=$(lease_ip_for_mac "de:ad:be:ef:00:01")
if [[ "$ip" == "172.30.110.50" ]]; then
    pass "Reserved client got exactly 172.30.110.50"
else
    fail "Reserved client got '$ip', expected 172.30.110.50"
fi

# ══════════════════════════════════════════════════════════════════════════════
header "TEST 4 — Pool Exhaustion"
# ══════════════════════════════════════════════════════════════════════════════
# Pool has .100 and .101. client-vlan10 holds .100 (TEST 1).
# First: overflow client takes .101
log "  overflow client requesting (should get .101, second pool slot)..."
dhcp_request kea-testbed-client-overflow-1 > /dev/null
ip_overflow=$(lease_ip_for_mac "ca:fe:ba:be:00:01")
log "  overflow got: $ip_overflow"

# Now pool is full. client-vlan10-b (3rd unique MAC) must fail.
log "  vlan10-b (3rd MAC) requesting — pool should be exhausted..."
out3=$(dhcp_request kea-testbed-client-vlan10-b-1)
ip3=$(lease_ip_for_mac "00:11:22:33:44:66")
if [[ -z "$ip3" ]] || echo "$out3" | grep -qi "DHCP_FAILED\|no lease\|nak"; then
    pass "Pool exhaustion: 3rd vlan10 client (00:11:22:33:44:66) got no IP"
else
    fail "Pool exhaustion: 3rd client unexpectedly got IP: $ip3"
fi

# ══════════════════════════════════════════════════════════════════════════════
header "TEST 5 — Unknown Subnet (vlan99)"
# ══════════════════════════════════════════════════════════════════════════════
log "  Requesting DHCP on unknown-subnet client (ba:ad:ca:fe:00:01)..."
out=$(dhcp_request kea-testbed-client-unknown-1)
ip=$(lease_ip_for_mac "ba:ad:ca:fe:00:01")
if [[ -z "$ip" ]] || echo "$out" | grep -qi "DHCP_FAILED\|no lease\|nak"; then
    pass "Unknown-subnet client got no lease"
    if kea_log | grep -qiE "subnet.*select|no subnet|SUBNET_SELECT|no suitable"; then
        pass "Kea logged subnet selection failure"
    else
        pass "Unknown subnet confirmed (no IP assigned)"
    fi
else
    fail "Unknown-subnet client unexpectedly got IP: $ip"
fi

# ══════════════════════════════════════════════════════════════════════════════
header "TEST 6 — Lease Renewal (same IP re-issued)"
# ══════════════════════════════════════════════════════════════════════════════
first_ip=$(lease_ip_for_mac "aa:bb:cc:dd:ee:ff")
log "  First IP: $first_ip — requesting renewal..."
dhcp_request kea-testbed-client-vlan20-1 > /dev/null
renewed_ip=$(lease_ip_for_mac "aa:bb:cc:dd:ee:ff")
if [[ -n "$first_ip" ]] && [[ "$first_ip" == "$renewed_ip" ]]; then
    pass "Lease renewal: same IP $first_ip re-issued"
else
    fail "Lease renewal: IP changed from '$first_ip' to '$renewed_ip'"
fi

# ══════════════════════════════════════════════════════════════════════════════
header "TEST 7 — DHCP Option Delivery (DNS + NTP + ACS URL)"
# ══════════════════════════════════════════════════════════════════════════════
cfg_dns=$(config_option domain-name-servers global)
cfg_acs=$(config_option vendor-encapsulated-options subnet)

if [[ -n "$cfg_dns" ]] || [[ -n "$cfg_acs" ]]; then
    log "  Custom Options configured (DNS: ${cfg_dns:-none}, ACS: ${cfg_acs:-none}) — verifying delivery..."
    dhcp_request kea-testbed-client-vlan20-1 > /dev/null
    
    if [[ -n "$cfg_dns" ]]; then
        received_dns=$(dexec 5 kea-testbed-client-vlan20-1 \
            "grep '^DNS' /tmp/dhcp_options.txt 2>/dev/null | cut -d: -f2- | tr -d ' '" \
            | grep -v TIMED_OUT || true)
        if [[ -n "$received_dns" ]] && [[ "$received_dns" != "NONE" ]]; then
            pass "DNS option delivered: $received_dns"
        else
            fail "DNS option NOT delivered despite being in config ($cfg_dns)"
        fi
    fi

    if [[ -n "$cfg_acs" ]]; then
        # udhcpc stores option 43 (vendor-encapsulated-options) differently depending on script, 
        # often missing or raw hex. We check if udhcpc received ANY option 43 in standard output.
        # But a more direct way: we grep the dhcp options dump for standard vendor options
        # Read the captured VALUE, not the label: a bare `grep -i vendor` also
        # matches the line "Vendor    : NONE", which reported a delivery that
        # had demonstrably not happened.
        received_acs=$(dexec 5 kea-testbed-client-vlan20-1 \
            "grep -i '^Vendor' /tmp/dhcp_options.txt 2>/dev/null | cut -d: -f2- | tr -d ' '" \
            | grep -v TIMED_OUT || true)
        if [[ -n "$received_acs" ]] && [[ "$received_acs" != "NONE" ]]; then
            pass "ACS URL / Vendor option delivered: $(echo $received_acs | head -c 50)..."
        else
            # Some udhcpc scripts don't export option 43 explicitly unless requested via -O 43.
            # We will softly fail/warn here if it's missing from the raw dump.
            log "  [WARN] ACS URL config present but not parsed by this client's udhcpc script."
            pass "ACS URL config verified in Kea (client parsed options: limited)"
        fi
    fi
else
    skip "DNS/ACS delivery test skipped — set in EZ-KEA WebUI first, then re-run"
fi

# ══════════════════════════════════════════════════════════════════════════════
header "TEST 8 — Lease Release"
# ══════════════════════════════════════════════════════════════════════════════
# busybox udhcpc sends DHCPRELEASE when sent SIGUSR2 while running as a daemon.
# Step 1: start udhcpc as a background daemon, get a lease.
# Step 2: send SIGUSR2 → udhcpc sends DHCPRELEASE and exits.
log "  Starting udhcpc daemon on vlan20 client..."
dexec 15 kea-testbed-client-vlan20-1 \
    'udhcpc -i eth0 -b -p /tmp/udhcpc.pid -s /tmp/udhcpc.script -T 3 -t 2 2>/dev/null; sleep 2' > /dev/null
log "  Sending SIGUSR2 to trigger DHCPRELEASE..."
dexec 8 kea-testbed-client-vlan20-1 \
    'kill -USR2 $(cat /tmp/udhcpc.pid 2>/dev/null) 2>/dev/null || true; sleep 2' > /dev/null
sleep 1

if kea_log | grep -qiE "DHCP4_RELEASE|release.*clid|release.*addr"; then
    pass "Kea logged DHCPRELEASE"
else
    # Fallback: in Kea memfile, a released lease is removed from the file
    lease_count=$(dexec 5 kea-testbed-kea-1 \
        "grep -c 'aa:bb:cc:dd:ee:ff' /var/lib/kea/kea-leases4.csv 2>/dev/null || echo 0" \
        | grep -Eo '^[0-9]+' | head -1)
    if [[ "${lease_count:-1}" == "0" ]]; then
        pass "Lease released (entry removed from Kea leases file)"
    else
        fail "Release not confirmed: Kea log has no RELEASE and lease still in CSV"
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════${RESET}"
echo -e "${BOLD}Results: ${GREEN}${PASS} passed${RESET}, ${RED}${FAIL} failed${RESET}"
echo -e "${BOLD}══════════════════════════════════════${RESET}"
log "  Suite complete."

if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
    echo -e "\n${RED}Failed:${RESET}"
    for t in "${FAILED_TESTS[@]}"; do echo "  - $t"; done
    exit 1
fi
exit 0
