# EZ-KEA Pre-Launch Audit — Findings

**Date:** 2026-07-08
**Scope:** Full source review + live black-box/white-box testing against two running instances (a DEMO-mode sandbox and a LIVE instance wired to a real `kea-dhcp4` in the Docker testbed under `testbed/`), plus real DHCP protocol testing against simulated VLAN clients.
**Method:** Five parallel audit passes (security, functional fuzzing, network/protocol, UI/UX, feature-gap analysis), cross-verified — several of the most severe findings were independently rediscovered by 2-3 agents from different angles, which is noted inline as corroboration. A handful of the highest-severity claims were also spot-checked directly against source by hand before being written up here.
**Status when written:** Audit only. No source files were modified. Fixes were not yet applied — this document was the punch list for that follow-up work.

**Status now: remediated.** Every security and functional finding below has been
fixed and carries regression tests. See [Remediation status](#remediation-status)
for the per-finding breakdown and the one item that remains partially open.
Everything from the "Status when written" line down to the end of this document
is preserved as originally written, so the fixes can be checked against the
claims that prompted them — read it as a historical record, not as a live
description of the codebase.

---

## Remediation status

Verified against the codebase on 2026-07-29. The test suite (231 tests,
`python -m pytest`) includes regression tests for every finding marked **Fixed**;
many carry the original proof-of-concept as an executable test.

### 1. Security vulnerabilities — all closed

| # | Severity | Status | Fix |
| --- | --- | --- | --- |
| 1.1 | CRITICAL | **Fixed** | `ez_kea/core/security.py` validates Kea commands against an allowlist; PoC preserved in `tests/test_system_routes.py` |
| 1.2 | CRITICAL | **Fixed** | Path validation in `ez_kea/core/security.py:95`; PoC in `tests/test_security.py:108` |
| 1.3 | CRITICAL | **Fixed** | Config-file repoint is a distinct, validated action (`routes/system.py:430`); PoC in `tests/test_system_routes.py:612` |
| 1.4 | CRITICAL | **Fixed** | `CSRFProtect` app-wide (`ez_kea/__init__.py:43`); `tests/test_csrf.py` |
| 1.5 | CRITICAL | **Fixed** | Flask-Login on every route; binds `127.0.0.1` by default (`app.py`) |
| 1.6 | MEDIUM | **Fixed** | Startup warning, and a hard refusal to bind off-loopback with the default key (`app.py:17`) |
| 1.7 | HIGH | **Fixed** | `ez_kea/core/config_manager.py:258`; `tests/test_config_manager.py:67` |
| 1.8 | MEDIUM | **Fixed** | `with_config_lock()` on all config writes (`config_manager.py:150`) |
| 1.9 | LOW | **Fixed** | `validate_option_data()` rejects control chars and angle brackets |
| 1.10 | LOW | **Fixed** | `sanitize_hostname()` applied to lease hostnames (`validation.py:178`) |
| 1.11 | INFO | No action needed | Verified safe at audit time; unchanged |

### 2. Functional bugs — all closed

| # | Severity | Status | Fix |
| --- | --- | --- | --- |
| 2.1 | CRITICAL | **Fixed** | `pools()` passes standalone subnets to the template; `tests/test_dhcp4_routes.py:43` |
| 2.2 | CRITICAL | **Fixed** | Standalone subnets handled in `has_overlap()`, `return_available_ips()`, `new_reservation()` |
| 2.3 | HIGH | **Fixed** | In-container path settings + explicit reload strategy (`ez_kea/config.py:41-53`) |
| 2.4 | HIGH | **Fixed** | `_mac_reservation_sort_key()` tolerates malformed addresses |
| 2.5 | MEDIUM | **Fixed** | Malformed input handled across `/test-config`, `/apply-config`, lease parsing |
| 2.6 | MEDIUM | **Fixed** | `new_subnet6()` auto-creates the shared network instead of dropping the subnet |
| 2.7 | MEDIUM | **Fixed** | Timer, interface, and delegated-length validation added |
| 2.8 | — | — | Record of what worked; no action |

### 4. UI/UX — closed, except v4/v6 parity

| # | Status | Notes |
| --- | --- | --- |
| 4.1 | **Fixed** | All referenced classes now defined in `styles.css` |
| 4.2 | **Partially open** | See below |
| 4.3 | **Fixed** | Reservations can target standalone subnets |
| 4.4 | **Fixed** | Config toolbar present on the config-editing pages |
| 4.5 | **Fixed** | Inter and lucide vendored under `static/vendor/`; no external CDN references remain |
| 4.6–4.10 | **Fixed** | Colour, icon, terminology, contrast, and accessibility passes applied |
| 4.11 | **Fixed** | Responsive breakpoints at 900px and 600px, plus `prefers-reduced-motion` |
| 4.12 | **Fixed** | Favicon and app icons under `static/icons/`; naming consistent |
| 4.13 | **Fixed** | Flash messages rendered in `templates/base.html:77` |
| 4.14 | **Fixed** | Empty states and first-run flow implemented |

### Still partially open

**4.2 / 5.1 — DHCPv4 and DHCPv6 are not yet at full parity.** Most of the gap
has closed: DHCPv6 now has subnets, pools, prefix delegation, DUID reservations,
per-subnet options, leases, and HA. One concrete gap remains — the DHCPv6 Pools
view (`routes/dhcp6.py:48`) renders only shared-network subnets, and
`new_subnet6()` always nests new subnets into a shared network. Standalone
`Dhcp6.subnet6[]` entries are therefore readable by the options routes but
invisible in the UI. DHCPv4 handles this correctly.

### 5. Roadmap items

Section 5 is a commercialization roadmap rather than a defect list. The
must-have items identified there — authentication, 2FA, user management, HA
support, and DHCPv6 — have since been implemented.

---

## TL;DR

> The TL;DR and all sections below describe the codebase **as it was on
> 2026-07-08**, before any fixes. They are retained unedited as the historical
> record. For current status, see [Remediation status](#remediation-status) above.

EZ-KEA's core DHCPv4 CRUD (subnets, pools, options, timers) is solid, but the app **cannot safely be exposed to any untrusted network today**, has a crash bug in its main page triggered by following the UI's own default recommendation, and has a silent data-loss bug that breaks MAC reservations for the more common of its two subnet types. None of this is hard to fix, but none of it should ship as-is either. Priority order:

1. Fix the `/pools` crash (`templates/pools.html:144`) — one-line fix, breaks the main page today.
2. Fix the standalone-subnet blind spot in `has_overlap()`, `return_available_ips()`, and `new_reservation()` (`ez_kea/core/validation.py`, `ez_kea/routes/dhcp4.py`) — silently drops reservations and lets duplicate/overlapping standalone subnets through.
3. Stop building shell commands and file paths from unvalidated user input (`ez_kea/routes/system.py`) — this one architectural change closes three Critical security findings at once.
4. Add authentication + CSRF protection before this is ever bound to anything other than `127.0.0.1`.
5. Decide the Docker deployment story for `/apply-config` — it cannot succeed at all as currently documented in `testbed/README.md`.

---

## 1. Security Vulnerabilities

### 1.1 [CRITICAL] Arbitrary command execution via `kea_dhcp4_cmd` / `kea_ctrl_cmd`
**File:** `ez_kea/routes/system.py:38` (`/test-config`), `:59` (`/apply-config`); persisted at `:150-156` (`/save-global-settings`).
**Confirmed by:** security-auditor + qa-fuzzer independently, both with live PoC.

`kea-dhcp4-cmd`/`kea-ctrl-cmd` are free-text form fields, saved verbatim to `ez-kea-settings.json`, and immediately applied to `current_app.config`. They're later used as:
```python
command = shlex.split(f'{current_app.config["KEA_DHCP4_CMD"]} -t {current_app.config["DHCP_CONFIG_FILE"]}')
subprocess.run(command, capture_output=True, text=True, check=True)
```
No `shell=True`, but `shlex.split()` on attacker input means the attacker chooses `argv[0]` — the exact program executed. Live PoC (both the plain DEMO instance **and** the "LIVE/dockerized" instance — the vulnerable `subprocess.run` runs on the **host** either way, so wrapping the command in `docker exec` provides zero real sandboxing):
```bash
curl -s -X POST http://localhost:8080/save-global-settings --data-urlencode "kea-dhcp4-cmd=/tmp/evil.sh"
curl -s -X POST http://localhost:8080/test-config
# {"message":"Syntax check passed!"} — evil.sh executed as the OS user (kaleb, in sudo+docker groups)
```
**Fix direction:** never build exec commands from user-controlled strings. Use a fixed, non-editable allowlist of vetted binary paths (or a small enum), validate the path resolves to a known-good non-writable-by-app binary, and drop the free-text field entirely.

### 1.2 [CRITICAL] Arbitrary local file read via `dhcp_log_file` + `/logs`
**File:** `ez_kea/routes/system.py:76-87`, setter at `:155`.
**Confirmed by:** security-auditor, live PoC.

`dhcp_log_file` is free text with no path confinement; `/logs` opens whatever it's set to and renders up to the last 1000 lines (with keyword search built in).
```bash
curl -s -X POST http://localhost:8080/save-global-settings --data-urlencode "dhcp-log-file=/etc/passwd"
curl -s http://localhost:8080/logs | grep "root:"
# root:x:0:0:root:/root:/bin/bash  <- rendered in the UI
```
**Fix direction:** restrict to files under a fixed, configured log directory; resolve + `os.path.commonpath` check against an allowlisted root; reject anything outside it.

### 1.3 [CRITICAL] Arbitrary local file write/overwrite via `dhcp_config_file`
**File:** `ez_kea/routes/system.py:110-188`, `ez_kea/core/config_manager.py:73-90` (`save_json`).
**Confirmed by:** security-auditor, live PoC.

`/save-global-settings` unconditionally ends with `save_json(config, current_app.config["DHCP_CONFIG_FILE"])` — and `DHCP_CONFIG_FILE` may have just been repointed, in the same request, to any attacker-chosen path. There is no separate "confirm write" step, and `save_json` auto-creates parent directories. Live PoC destroyed a canary file's contents on the very first request naming it as the new config path — no second click needed.

**Fix direction:** treat a `dhcp_config_file` change as a distinct "repoint" action that does not also trigger a save in the same request; confine to an allowlisted directory or require the target already be a valid Kea config.

### 1.4 [CRITICAL] No CSRF protection on any state-changing route
**Files:** every template under `templates/` (`grep -rn csrf` = zero hits); every mutating route in `system.py`/`dhcp4.py`/`dhcp6.py`/`options.py`.
**Confirmed by:** security-auditor + product-analyst, live PoC.

No CSRF tokens, no Origin/Referer check, and (since there's no auth either) no cookie to scope a SameSite defense to. Confirmed: a forged-Origin POST from `http://evil.example.com` succeeded identically to a same-origin request. Because this is a plain `<form>` POST with no custom headers or JSON body required, **a single hostile webpage the victim's browser merely loads** is sufficient to pivot straight into 1.1 (RCE) with zero user interaction beyond visiting a page while able to route to the port.

**Fix direction:** add CSRF tokens (Flask-WTF/flask-seasurf) to every mutating form.

### 1.5 [CRITICAL] No authentication/authorization anywhere; binds `0.0.0.0` by default
**Files:** `app.py:10`, entire `ez_kea/routes/*` (zero hits for `login|authenticate|Authorization`).
**Confirmed by:** security-auditor + product-analyst.

```python
serve(app, host="0.0.0.0", port=port)
```
This is the hardcoded default the moment `python3 app.py` runs with zero configuration — confirmed both instances listened on `0.0.0.0`. Combined with 1.1–1.4: **anyone who can route a TCP packet to the port gets unauthenticated RCE and arbitrary file read/write.** The README's systemd instructions (persistent background daemon) widen this exposure window rather than mitigating it.

**Fix direction:** add a login/session layer in front of every route (even HTTP basic auth over TLS beats nothing); default-bind `127.0.0.1` unless the operator explicitly opts into a wider bind with auth enabled.

### 1.6 [MEDIUM] `SECRET_KEY` defaults to the literal string `"dev"`
**File:** `ez_kea/config.py:12`.
**Confirmed by:** product-analyst, verified directly.

No startup check forces an operator to override this in production. Undermines any session-based auth added later. Table-stakes fix once 1.5 lands: fail startup (or warn loudly) if `SECRET_KEY` is still the default and the app isn't bound to localhost.

### 1.7 [HIGH] Backup/restore path confusion — `copy_file(restore=True)`
**File:** `ez_kea/core/config_manager.py:151-177`.
**Confirmed by:** security-auditor, mechanically exercised live.

Restore selects the file with the largest trailing timestamp among **any** file containing `.bak.` in `backup_dir` — no check that the backup's filename corresponds to the *current* `config_file`. Since `dhcp_config_file` is fully attacker-settable (1.3) while `backup_dir` is fixed, an attacker (or just an operator who's pointed EZ-KEA at more than one config file over its lifetime — e.g. switching DEMO/LIVE) can get `/restore-config` to silently overwrite the active config with content that was backed up for a completely different file.

**Fix direction:** name backups by a hash/exact match of the full config path, and filter restore candidates to only those matching `config_file` before comparing timestamps.

### 1.8 [MEDIUM] Lost-update race condition on concurrent config writes
**File:** `ez_kea/core/config_manager.py:48-90`, used by every mutating route's load→mutate→save cycle.
**Confirmed by:** security-auditor + qa-fuzzer independently, both with live concurrency tests.

`fcntl.flock` only guards the individual read/write syscall, not the full cycle. Firing 15 concurrent `/new-shared-network` + 15 concurrent `/new-subnet` POSTs: only 3/15 and 10/15 survived, respectively — every request returned HTTP 200/302 "success," but roughly a third of writes were silently discarded. A second, independent 12-request test on `/new-subnet` alone lost 4/12 (33%). This is a real, easily-triggered bug any time two admins (or a script + the UI) hit the app close together, not just theoretical.

**Fix direction:** hold a single exclusive lock across the entire load→mutate→save cycle per config file, or move to a datastore with atomic updates/optimistic concurrency and reject stale writes with a clear error instead of silently dropping them.

### 1.9 [LOW] XSS surface reviewed — no live exploit today, but fragile
**Files:** all templates; `ez_kea/routes/options.py`.
**Confirmed by:** security-auditor, live-tested with a literal `<script>` payload in `option-data`.

Jinja autoescaping is consistently on everywhere; the only `|safe` usage (`templates/new_reservation.html:82`, `{{ subnet_data | tojson | safe }}`) is not exploitable since `tojson` itself escapes for script-context embedding. A stored `<script>alert(document.cookie)</script>` in `option-data` (which has **zero server-side sanitization**) round-trips as escaped text in the browser — no execution. Not a live bug, but relies entirely on the template layer never adding another `|safe`.

**Fix direction:** keep autoescaping everywhere; additionally validate/sanitize `option-data` server-side (reject control characters/angle brackets) since it's serialized into files real DHCP clients will parse.

### 1.10 [LOW] `sanitize_hostname()` inconsistently applied
**File:** `ez_kea/core/validation.py:30-34`; applied only at `ez_kea/routes/dhcp4.py:199`.
**Confirmed by:** security-auditor.

Not applied to lease-derived hostnames (`get_active_leases()`, which parses whatever a DHCP client sends via the hostname option, no sanitization) or to `option-data`. Currently masked by autoescaping (1.9), but the sanitizer is clearly meant to be the source-of-truth defense and is silently bypassed on other hostname-shaped paths.

### 1.11 [INFORMATIONAL] `<path:subnet>` URL converter — verified safe
**File:** `ez_kea/routes/options.py:8,57,77,114`.

Tested directly with path traversal (`..%2F..%2Fetc%2Fpasswd`), null bytes, a 100,000-char string, and extra path segments — all correctly 404 with no crash. `subnet` is only ever used as a dict-key/string-equality match, never a filesystem path. No exploitable behavior found.

---

## 2. Functional Bugs

### 2.1 [CRITICAL — crash] `/pools` 500s permanently as soon as any standalone subnet exists
**File:** `templates/pools.html:144` vs. the real endpoint name `ez_kea/routes/options.py:78`.
**Confirmed independently by: security-auditor, qa-fuzzer, AND ui-ux-reviewer** (three separate passes, same root cause, same line). Personally re-verified against source in this session.

```jinja
{{ url_for('main.options.manage_subnet4_standalone_options', subnet=subnet.subnet) }}
```
but the actual registered function is `manage_standalone_subnet4_options` (word order swapped). `url_for()` raises `BuildError`, which propagates as an unhandled 500 for the **entire** `/pools` page — not just the broken link.

This is not a cold edge case: the page's own empty state and header button label "Add Standalone Subnet" as **"(Recommended)."** The moment any user follows the app's own default guidance, the main DHCPv4 dashboard becomes permanently unreachable until someone hand-edits the JSON or issues raw `/delete-subnet` POSTs via curl (the delete button lives on the page that's now crashing).

**Fix:** one-line — correct the endpoint name in `pools.html:144` to `main.options.manage_standalone_subnet4_options`. Add a regression test that renders `/pools` with a non-empty `standalone_subnets` list.

### 2.2 [CRITICAL — silent data loss] Reservations into standalone subnets are silently dropped
**Files:** `ez_kea/routes/dhcp4.py:204-219` (`new_reservation`), `ez_kea/core/validation.py:104-144` (`return_available_ips`), `ez_kea/core/validation.py:57-78` (`has_overlap`), `dhcp4.py:230` (`delete_reservation`).
**Confirmed independently by: qa-fuzzer, network-engineer (via real DHCP behavior), AND ui-ux-reviewer** (via the reservation form's dropdown). This is the single most-corroborated finding in the whole audit.

All of `new_reservation()`, `return_available_ips()`, `has_overlap()`, and `delete_reservation()` only ever traverse `Dhcp4.shared-networks[].subnet4[]` — never top-level `Dhcp4.subnet4[]` (the standalone list that `new_subnet()` creates by default when no shared-network name is given). Effect:
- The `/new-reservation` form's own subnet dropdown is empty for any standalone subnet — a user can't even attempt it through the UI.
- If a request is crafted directly (bypassing the empty dropdown), the route returns **HTTP 302 "success"** and redirects to the reservations list — but nothing is written anywhere. No error, no indication anything went wrong.
- Confirmed against **real Kea**: a reservation POST for a standalone subnet's MAC never appeared in the config, and the client never got the reserved IP over real DHCP. The identical reservation succeeded once the same subnet was moved inside a named shared network.
- `has_overlap()` has the mirror bug: exact-duplicate, superset, and subset standalone subnets are all silently accepted as non-overlapping (verified with `192.168.1.0/24` submitted twice, plus a `/16` superset and a `/25` subset) — a real Kea daemon would refuse to start with the resulting config.

**Fix direction:** make all four functions also walk `Dhcp4.subnet4[]`. Also add server-side validation that errors (rather than silently 302s) when the posted `subnet` can't be matched to any known subnet at all.

### 2.3 [HIGH — structural] `/apply-config`/`/test-config` cannot succeed at all in the documented Docker deployment
**File:** `ez_kea/routes/system.py:35-64`.
**Found by:** network-engineer, fully characterized against the real testbed.

`testbed/README.md` documents setting `KEA_DHCP4_CMD`/`KEA_CTRL_CMD` to `docker exec kea-testbed-kea-1 kea-dhcp4`/`keactrl` for a Docker deployment. But EZ-KEA builds the syntax-check/reload command using the **host** path of `DHCP_CONFIG_FILE`, while `docker exec` runs `kea-dhcp4` inside the **container's own filesystem namespace**, where that host path doesn't exist (the volume mount only exposes it at `/etc/kea/kea-dhcp4.conf` inside the container). This is a 100%-reproducible failure, unrelated to whether the JSON is valid:
```
$ curl -s -X POST http://localhost:8081/test-config
{"error":"...Unable to open file /home/kaleb/dev/ez-kea/testbed/data/etc/kea/kea-dhcp4.conf"}
```
`/apply-config` calls `test_config()` first and returns immediately on failure, so `KEA_CTRL_CMD reload` is **never even reached**. Even if that were fixed, `keactrl reload` independently fails in this container because `/etc/kea/keactrl.conf` isn't mounted (exactly as `testbed/README.md`'s own footnote warns) — two independent blockers, both must be fixed. The only mechanism that actually reloads Kea here is `docker kill -s HUP kea-testbed-kea-1`, which EZ-KEA's code has no path to trigger.

**Verdict:** a genuine deployment-model bug, not a testbed misconfiguration — EZ-KEA has no concept that "the command I shell out to may run in a different filesystem namespace than the config file I manage." Following the product's own Docker instructions produces an instance where the single most important action ("Apply Changes") can never succeed.

**A related, same-root-cause bug:** `save_global_settings()` always writes a guessed Docker-style logger path (`/var/log/kea/kea-dhcp4.log`) into the Kea config. Inside the container, that directory doesn't exist, so Kea's **own** logging silently dies (`docker logs` goes permanently quiet the moment this is set) — and EZ-KEA's `/logs` viewer tries to open that same path on the **host**, where it also doesn't exist, so it shows "No log entries found" forever, regardless of real traffic. This blinds both the product's log viewer and the operator's fallback simultaneously.

**Fix direction:** either require host-path==container-path bind mounts (validate at startup) or add an explicit "in-container path" setting distinct from "path EZ-KEA reads/writes," and use the latter only for exec'd commands. Handle the missing-`keactrl.conf` case explicitly, offering a "container SIGHUP" reload mode as first-class supported behavior.

### 2.4 [HIGH — crash] `/mac-reservations` 500s on any reservation with a malformed `ip-address`
**File:** `ez_kea/routes/dhcp4.py:177`.
**Found by:** qa-fuzzer (matches a bug the audit brief specifically asked to check for).

```python
mac_reservations.sort(key=lambda x: [int(p) for p in x.get("ip-address","0.0.0.0").split(".")])
```
`new_reservation()` never validates that the submitted `ip-address` is a syntactically valid IPv4 address (only checks non-empty), so a reservation created through the app's own form with e.g. `ip-address=not-an-ip-address` permanently crashes the reservations page for everyone — and the only way to remove the bad entry is a raw `/delete-reservation` POST, since the UI page needed to do it is the one that's broken.

**Fix direction:** validate `ip-address` is a real IPv4 address at submission time (reject with a form error, matching the pattern already used for MAC validation); defensively wrap the sort key regardless.

### 2.5 [MEDIUM — crash] Several unhandled 500s on malformed input
**Confirmed by:** qa-fuzzer + security-auditor.

- `/save-global-settings` 500s on a non-numeric timer value (`system.py:124`, bare `int()` with no try/except) — no graceful error, unlike the subnet/reservation routes which use an `errors` list.
- `/leases` **and** `/new-reservation` (which shares the same helper) both 500 on a malformed `expire` value in the leases CSV (`validation.py:90`) — a truncated/corrupted write from a disk-full event or a Kea crash (a realistic real-world scenario for a lease store) takes down two core pages at once. Missing and empty lease files are both handled gracefully; only malformed *values* crash.
- `/test-config`/`/apply-config` only catch `subprocess.CalledProcessError`, so a missing Kea binary raises an uncaught `FileNotFoundError` → raw Flask 500 instead of the app's own JSON error format.

**Fix direction:** wrap all three in try/except with sane fallbacks and friendly 400-level errors instead of letting them propagate to unhandled 500s.

### 2.6 [MEDIUM — silent data loss] `/new-subnet6` silently drops the subnet on missing/nonexistent shared-network-name
**File:** `ez_kea/routes/dhcp6.py:100-117`.
**Found by:** qa-fuzzer.

Unlike the v4 equivalent (which auto-creates the shared network if the name doesn't match one), the v6 route has no `else` branch — if `shared_network_name` doesn't match anything (including when the field is omitted entirely), the loop body never runs, yet `save_json()` + `redirect()` still fire as if it succeeded. Confirmed: neither of two IPv6 subnets submitted this way end up anywhere in the config.

### 2.7 [MEDIUM — incorrect validation] Miscellaneous validation gaps
**Found by:** qa-fuzzer.

- Global timers (`valid-lifetime` etc.) accept negative, zero, and arbitrarily large values with no bounds check (`system.py:122-128`) — Kea itself requires positive integers and would fail to reload.
- IPv6 PD `delegated-len` accepts out-of-range values including `0` and `999999` (`dhcp6.py:89-95,110-111`) — only checked via `isdigit()`, no range validation; a negative value produces a misleading "required" error even though a value was supplied.
- Hostname's "required" check runs on the *raw* value before `sanitize_hostname()` strips it — an all-emoji hostname (`😀🔥🎉`) passes the non-empty check but sanitizes down to an empty string, silently storing a blank hostname despite the form enforcing "required" (`validation.py:30-34`, `dhcp4.py:195-199`).
- `interfaces-config` accepts garbage/duplicate interface names with no validation or de-duplication (`system.py:117-120`).
- No warning when a subnet's router IP falls inside its own dynamic pool range (best-practice gap, not a hard Kea requirement).

### 2.8 What worked correctly (no bugs found)
HTTP method enforcement (405 on wrong verb), Content-Type handling (multipart vs urlencoded), delete-* idempotency including concurrent double-delete, shared-network deletion cascade (no orphaned data), options update-in-place, `/logs` search (plain substring match, immune to ReDoS — tested with a 100k-char query and regex metacharacters), missing/empty leases file handling, IPv6 host-bit-set rejection, and shared-network-to-shared-network overlap detection all behaved correctly.

---

## 3. Network / Protocol Findings (Docker testbed)

**Baseline `testbed/test_suite.sh` run (empty config):** 4 passed / 4 failed — expected for an empty config; also surfaced that the base Kea container starts with **no `interfaces-config` at all**, so it can't answer any DHCP traffic until an operator explicitly configures interfaces. `testbed/README.md` doesn't call this out, so a new user following its own instructions will find every test client fails until they separately discover this requirement.

**After building a real config entirely through the EZ-KEA UI** (subnet, pool, reservation, options) and manually reloading via `docker kill -s HUP kea-testbed-kea-1` (the only working reload mechanism — see 2.3): 6 passed / 3 failed, with all 3 residual failures attributable to no vlan20 subnet being configured (out of this audit's scope, not a new defect).

**Scenario results, driven end-to-end through the live UI and verified against real DHCP behavior:**

| Scenario | Result |
|---|---|
| Create standalone subnet + pool, client obtains dynamic lease | PASS (once real reload used) |
| MAC reservation on a **standalone** subnet | **FAIL — silent no-op, see 2.2** |
| Same reservation after moving the subnet into a shared network | PASS |
| Pool exhaustion (2-IP pool, 3rd distinct client gets nothing) | PASS |
| Unknown-subnet client (vlan99, no Kea subnet configured) gets no lease | PASS |
| Router + DNS option delivery, verified in real DHCP ACK | PASS |

Everything that successfully reached a running Kea config behaved with 100% fidelity to what the UI reported — the gaps are entirely in getting changes to actually reload (2.3) and in the standalone-subnet blind spot (2.2), not in Kea misinterpreting anything EZ-KEA wrote.

---

## 4. UI/UX Inconsistencies

*(No browser/screenshot tool was available to any review pass; findings below come from reading every template/CSS file directly, cross-referencing against route handlers, and rendering pages via curl and the Flask test client against fixture data.)*

### 4.1 [HIGH] Three CSS classes used throughout templates are never defined in `styles.css`
`.text-secondary` (6 uses across 5 files), `.btn-sm` (13 uses across 5 files), `.d-inline` (7 uses across 2 files) — none exist in `static/css/styles.css`. Effect: "secondary" text renders full-bright instead of muted, and every compact inline action button (Delete, Options, etc.) renders at full button size instead of the intended compact size, crowding table rows. Reads as unfinished CSS on nearly every page.

### 4.2 [HIGH] IPv4 and IPv6 are not the same product
The nav presents "DHCPv4" and "DHCPv6" as parallel sections. They are not: v6 has no standalone subnets, no per-subnet options UI, no MAC/DUID reservations at all (despite `dhcp6.py` writing an empty `reservations: []` into every new v6 subnet that nothing can ever populate), no Global Settings equivalent, no leases view, and no logs view. None of the nav labels ("Reservations," "Settings," "Logs," etc.) are qualified as v4-only, so a dual-stack customer has every reason to expect parity that silently isn't there. (See also Feature Gaps §5 — this is corroborated from the source-analysis side too.)

### 4.3 [HIGH] New Reservation form silently can't target standalone subnets
Same root cause as bug 2.2, visible in the UI itself: the subnet dropdown on `/new-reservation` simply omits any standalone subnet, with no explanation — combined with 2.1, the app's own "recommended" default path is a dead end for two core features (you can create the subnet, but never reserve on it, and viewing Pools afterward crashes).

### 4.4 [MEDIUM-HIGH] "Apply Changes" toolbar missing from the pages that need it most
`config_buttons.html` (Backup/Restore/Test/Apply) is only included on `index.html`, `pools.html`, `pools6.html` — absent from `global_settings.html`, `mac_reservations.html`, `manage_options.html`, even though those pages mutate the same config file. After saving settings or adding a reservation, there's no visible path to push the change live without navigating elsewhere.

### 4.5 [MEDIUM] Unpinned CDN dependencies with no offline fallback, plus JS-only buttons with dead form scaffolding
Every page loads Google Fonts and an **unversioned** (`@latest`) Lucide icon library with no self-hosted fallback — every icon (including icon-only delete buttons) silently disappears if the admin box lacks general internet egress, which is common for network-management tools deployed on isolated management VLANs. Separately, the "Test Syntax"/"Apply Changes" buttons are `type="button"` inside a `<form>`, so the surrounding form (including its `onsubmit="confirm(...)"` safety check) can never actually fire — dead code that only works today because a separate JS `addEventListener` handles the click directly.

### 4.6 [MEDIUM] Color-coding contradicts itself within one page
On `pools.html` (the v4 page), "Shared Network" is tinted blue while "Standalone Subnets" — a section on the same page — is tinted the same green used to mean "IPv6" everywhere else in the app (`pools6.html`'s shared-network header, v6 badges). A user skimming color will misread the standalone section as IPv6-related.

### 4.7 [MEDIUM] Icon reuse collides across pages
`globe` means "DHCPv6" in the nav and on the v6 page header, but also means "Global Settings" on the dashboard — which additionally uses a *different* icon (`hexagon`) for its own DHCPv6 tile. No single icon consistently anchors "this means IPv6."

### 4.8 [MEDIUM] Terminology drift within a single page
On `pools.html` alone: "Router Data" vs. "Router," "Available Pools" vs. "Pool," "Manage Options" vs. "Options" — same concepts, different wording between the shared-network and standalone sections placed directly above one another.

### 4.9 [MEDIUM] `.btn-primary` text contrast fails WCAG AA
White text (`#ffffff`) on primary-blue (`#3b82f6`) computes to **3.68:1** (WCAG AA requires 4.5:1 for normal-weight text) — and `.btn-primary` is the most-used interactive class in the app ("Apply Changes," "Create Subnet," "Save Settings," etc.). All other checked color pairs pass.

### 4.10 [LOW-MEDIUM] Accessibility gaps
The standalone-subnet delete button (`pools.html:150`) has no visible text and no `title`/`aria-label`, unlike every other delete button in the app (all of which do have a `title`). The log search input has no associated `<label>`, relying on placeholder text alone.

### 4.11 [LOW] Zero responsive breakpoints
`grep -c "@media" static/css/styles.css` → 0. The 7-item nav bar has no collapse/hamburger behavior and several form grids use fixed `1fr 1fr 1fr 1fr` columns with no narrow-viewport fallback (though the pattern for a responsive `auto-fit, minmax(...)` grid already exists elsewhere in the same codebase — just applied inconsistently).

### 4.12 [LOW] Branding/naming inconsistency; no favicon
`<title>` fallback says "KEA-EZ" while the visible brand text says "EZ-Kea Dashboard" and page titles use yet a third form ("... - EZ-Kea"). No favicon is set anywhere — browser tab shows a generic icon.

### 4.13 [LOW] Flash-message infrastructure is half-built (currently dead code, but a trap for later)
`base.html` hardcodes blue "info" inline styling regardless of message category, so a `"danger"`-categorized flash would still render blue. No route currently calls `flash()` (current error display uses each form's own `errors` list, which works correctly) — flagged as a trap for whoever adds the first flash message, not a live bug.

### 4.14 Empty states and first-run experience
The Pools (v4) empty state is genuinely good (clear CTAs, one primary + one advanced option) and should be the template for the others — Reservations/Leases/Logs each use a different, less-polished empty-state pattern. `index.html` is static navigation cards with no state awareness at all (no "0 subnets, start here" prompt, no suggested order of operations, no live counts) — the single highest-leverage first-impression fix would be a dynamic "Getting Started" checklist driven off the same config data the Pools page already loads.

---

## 5. Missing Features / Roadmap for Commercialization

*(Source-level analysis, not a live-app test — see full reasoning per item in the original agent report if deeper rationale is needed later.)*

### 5.1 Verified gap beyond the assumed baseline: DHCPv6 is not real feature parity
There is no `DHCP6_CONFIG_FILE` config entry at all — every v6 route falls back to a hardcoded `./demo/kea-dhcp6.conf` if nothing else is set, which is always, since nothing else ever sets it. Auto-discovery (`discovery.py`) only ever scans for `kea-dhcp4`. No UI field exists to point EZ-KEA at a real v6 config on a live dual-stack box. No reservations, no options, no backup/restore, no syntax-test-before-reload for v6 at all — a broken v6 JSON can be pushed live with zero validation. (Corroborates UI finding 4.2.)

### 5.2 MUST-HAVE before selling
1. **Authentication** — no login/session gate anywhere (see 1.5).
2. **Fix the RCE via Kea-binary settings fields** (see 1.1) — non-negotiable regardless of auth.
3. **Fix arbitrary file read via log-file setting** (see 1.2).
4. **Override the default `SECRET_KEY`** and fail/warn loudly if it's still `"dev"` (see 1.6).
5. **HTTPS/TLS** — currently plain `waitress.serve()` with no TLS guidance beyond a bare systemd unit.
6. **CSRF protection** (see 1.4) — becomes a live attack vector the moment authenticated sessions exist.
7. **Audit trail** — `save_json()` silently overwrites with no user attribution or change log; "who deleted this subnet and when" is currently unanswerable even after auth lands.
8. **Licensing/entitlement hooks** — no license-check or feature-flag scaffold exists anywhere; land this before customers are running unlicensed copies.
9. **RBAC / admin-vs-viewer role split** — every referenced competitor (phpIPAM, Infoblox, Men&Mice) ships role separation.
10. **Fix the DHCPv6 config-file disconnect** (5.1) before marketing "IPv4 and IPv6 support" — a live demo against a real dual-stack box would expose this immediately.

### 5.3 Strongly recommended (competitiveness/retention)
1. **Config versioning with diff/rollback** beyond the current single-slot restore — backups already accumulate silently on disk with no list/diff UI; this is a cheap win since the data already exists.
2. **A real token-authenticated HTTP API** — every mutation today is an HTML form POST; no scriptable surface for automation/Terraform/CI exists beyond the read-only `/api/system/discover`.
3. **Multi-server/multi-site management** — the entire model is one Kea process, one config path; any customer with more than one Kea instance needs N separate EZ-KEA deployments with no shared view.
4. **HA/failover config support** — zero references to Kea's HA hook library anywhere.
5. **DDNS integration** — zero references to `ddns` anywhere; competitors treat DNS+DHCP+IPAM as one story.
6. **Client classes** — no support for VoIP/PXE/vendor-specific client classing.
7. **Notifications/alerting** — pool-exhaustion computation exists (`return_available_ips`) but nothing polls or alerts on it; no health-check on the Kea process beyond startup discovery.
8. **IPv6 reservations** (once 5.1 is fixed) — DUID/MAC-based static reservations are table stakes for real IPv6 deployments.
9. **Import/export** — no CSV/JSON export of subnets/reservations/leases anywhere.
10. **Dashboard with real usage stats/graphs** — `index.html` is static navigation cards only.
11. **Multiple pools per subnet from the UI** — Kea supports non-contiguous pools; the UI can only express one per subnet.
12. **Rate limiting / lease-limit config exposure** — unexposed Kea capability.

### 5.4 Nice-to-have / later
Vendor-specific option templates (PXE/TFTP, TR-069 ACS URL) beyond the three hardcoded global options; multi-tenant support (relevant only for MSP resale); SSO/SAML (once basic RBAC exists); a light-mode theme toggle (README claims "dark mode" as if it's a toggle — only one theme currently exists); a Terraform provider (natural follow-on once a real API exists); backup retention/cleanup policy for the currently-unbounded `./data/backups/` growth.

### 5.5 Structural note
The single-instance, single-Kea-process architecture (`Config.DHCP_CONFIG_FILE` as one path; discovery finds at most one process) isn't just a missing feature — it's an architectural decision that would need rework, not just new routes, to support the fleet/multi-site model most commercial buyers in this space expect as baseline.

---

## Appendix: Environment used for this audit

- **DEMO instance:** `http://localhost:8080`, isolated fixture data under a scratch directory (not the repo's real `./data/`, which was backed up before testing and left untouched).
- **LIVE instance:** `http://localhost:8081`, wired to `testbed/data/etc/kea/kea-dhcp4.conf`, with `KEA_DHCP4_CMD`/`KEA_CTRL_CMD` pointed at `docker exec kea-testbed-kea-1 ...`.
- **Testbed:** `testbed/docker-compose.yml`, brought up via `docker compose up -d --build` — real `kea-dhcp4` plus six simulated VLAN clients across three Docker networks.
- One incidental discovery during setup, worth fixing regardless of the rest of this audit: **EZ-KEA's auto-discovery can be confused by a containerized `kea-dhcp4` process that happens to be visible via a shared host `/proc`** (common on hosts where Docker doesn't fully isolate PID namespaces from root) — it binds to the container-internal config path (`/etc/kea/kea-dhcp4.conf`), which doesn't exist on the host, silently breaking. Worked around for this audit via pre-seeded settings files; not separately numbered above since it wasn't reached through the normal discovery flow a real deployment would use, but worth being aware of.
- `.env.testbed`, which `start_testbed.sh` expects to source, **does not exist in the repo** — the documented one-command testbed startup path is broken out of the box; the environment for this audit was instead set up manually with explicit env vars.

Both background app instances and the Docker testbed were left running at the end of this audit pending a decision on whether to keep them up for follow-up manual testing.
