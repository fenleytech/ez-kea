# Changelog

Notable changes to EZ-KEA. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While EZ-KEA is on `0.x`, environment variable names, settings keys, and the
on-disk layout under `data/` may still change between releases. Your Kea
configuration is never one of those things — EZ-KEA edits the file Kea already
reads and always backs it up first.

## [Unreleased]

### Fixed

High availability, found by running EZ-KEA's own HA output on two real Kea
3.2.1 servers, reached both through a DHCP relay and directly on a shared
segment. Every item below was reproduced there before the fix and passes
there after it.

- **HA configs EZ-KEA wrote never worked.** It loaded `libdhcp_ha.so` without
  `libdhcp_lease_cmds.so`, so the first lease sync failed (`'lease4-get-page'
  command not supported`) and both servers stayed in `syncing`/`waiting`,
  answering no clients at all. EZ-KEA now loads `lease_cmds` (from the HA
  library's directory unless it is already configured) and keeps the hook
  order ISC requires: `lease_cmds` and `flex_id` before HA, forensic logging
  after.
- **Load-balancing could hand one address to two clients.** Pools were left
  whole, so when the link between the servers dropped, both allocated from the
  same range (8 duplicate addresses out of 30 clients in the lab). EZ-KEA now
  splits every pool and DHCPv6 prefix pool in half with the `HA_<server>`
  classes Kea uses for load-balancing, re-splits whenever a subnet is added or
  edited, and joins the halves back when you leave load-balancing. Splits you
  tuned by hand are left alone.
- **A hostname in a peer URL broke the reload.** Kea's own config check
  accepts it, then the HA hook refuses to load. Peer URLs must now be IP
  addresses.
- **Peer URLs were described as Control Agent URLs**, which don't exist on
  Kea 3.2. EZ-KEA now writes the HA hook's `multi-threading` block with its own
  dedicated listener (the peer URL, port 8001 by convention) and refuses a URL
  whose port clashes with one of the server's HTTP control sockets.
- `max-unacked-clients` defaulted to 0, which turns off the check that stops a
  standby from taking over while its partner is still answering clients. It
  now defaults to ISC's 10. Max Response Delay must exceed Heartbeat Delay,
  and peer roles must fit the mode (hot-standby needs `primary` + `standby`,
  load-balancing `primary` + `secondary`).
- Saving the HA form dropped any HA setting it has no field for (TLS files,
  basic auth, tuned threads, a second relationship). Those are now kept.
- **Check Live Status always said "Request failed."** The buttons fetched the
  route's internal name instead of its URL. They now show the server's HA
  state, or the actual error (an unreachable control socket, an HTTP status).
- Changing the HA Mode left the peer Role dropdowns as they were, so switching
  hot-standby to load-balancing was rejected for the leftover `standby` role,
  and a fresh form started with two `primary` peers. The dropdowns now follow
  the mode: only that mode's roles are offered, `standby` and `secondary`
  carry across a switch, and added peers default to `backup`. A role mismatch
  is now one error that lists each peer's role, instead of two that read as if
  one peer had to be both `standby` and `backup`.

### Added

- **HA peer config sync.** Apply Changes now pushes this server's config to
  every HA partner, so nobody edits JSON on the second server. EZ-KEA talks to
  each peer's own Kea control API (Kea 3.x serves it over HTTP/HTTPS from the
  DHCP daemon; no Control Agent, SSH or second EZ-KEA). Each peer is set up
  once with a generated script that installs its config, the API and its
  credential files. After that, Apply tests the config on every peer, loads it
  there, reloads this server, then saves it to each peer's config file. If a
  peer can't load it, or this server's reload fails, the peers go back to
  their previous config and nothing is applied. A peer keeps its own
  interfaces, lease file, logging and control sockets. The HA page shows each
  peer as in sync, out of sync (including changes made outside EZ-KEA),
  unreachable or not managed. An unreachable peer stops Apply until you
  confirm applying on this server only.
- **Config file** download per peer for partners EZ-KEA doesn't manage: this
  server's config with only `this-server-name` changed.

- Adding a subnet to a config whose existing subnets have no explicit `id`
  assigned ID 1 (a missing `id` was counted as 0), colliding with the ID Kea
  had already assigned implicitly and recorded on every lease. New IDs now
  start above every explicit and implicit ID, for both DHCPv4 and DHCPv6.
- The homepage "Active Leases" card counted every address in the lease file,
  expired and reclaimed included, so a long-running install could show 149
  "active" leases with 14 actually live. It now counts only unexpired, active
  leases, the same definition the pool utilization bars already used.

## [0.9.2] — 2026-08-02

### Fixed

Found by a second from-scratch install, this time onto a fresh Ubuntu 26 VM
running ISC's own Kea 3.2 packages untouched — same premise as the 0.9.1 pass
below, different (and worse) bugs. All four are regression-tested; see
AUDIT_FINDINGS.md for the full write-up of each.

- **A Kea config full of ISC's own `//`/`#`/`/* */` comments — i.e. every
  packaged install's default config, unmodified — silently parsed as empty**
  instead of failing loudly, and saving anything on top of that emptied
  skeleton overwrote the real subnets/reservations on disk with no warning
  anywhere. `load_json()` now strips Kea's comment syntax before parsing, and
  a file that still fails to parse after that raises instead of silently
  returning a blank skeleton.
- **Saving Global Settings could still duplicate the logger's output-path key**
  and get the config rejected by Kea. 0.9.1 fixed the two places that *write*
  this key but missed that the skeleton default `load_json()` falls back to
  still hardcoded the old, wrong spelling — so the fallback path alone was
  enough to reproduce the exact bug 0.9.1 believed it had closed.
- **A config-parse fallback could leak one protocol's data into the other
  protocol's file.** The fallback skeleton was shared, mutable, module-level
  state, and one DHCPv6 route fetched the DHCPv4 skeleton by mistake when its
  own config didn't parse — together, creating an IPv6 subnet could write a
  stray `Dhcp4` block into `kea-dhcp6.conf`, which Kea then refused to load.
  The fallback is now always an independent deep copy, and every DHCPv6 call
  site was audited to fetch the right skeleton.
- **Every DHCPv6 Prefix Delegation pool created through the UI was rejected by
  Kea.** The only way to create one stored the whole `prefix/length` string as
  Kea's `prefix` field and never set the separate `prefix-len` field Kea's
  schema requires, so `kea-dhcp6 -t` failed with "missing parameter
  'prefix-len'" on every single one. Fixed to submit `prefix` and `prefix-len`
  as the separate fields Kea expects.

## [0.9.1] — 2026-07-31

### Fixed

Found by deploying from scratch onto a clean Ubuntu 24.04 box running ISC's own
Kea 3.2 packages — every one of these was reproduced on that machine, and all
are regression-tested in `tests/test_greenfield_regressions.py`.

- **Kea configs are now genuinely backed up before every write.** Automatic
  backup did not exist: `copy_file()` was reachable only from the explicit
  Backup and Restore buttons, while all 23 config-write paths (subnets, pools,
  reservations, options, HA, global settings) called `save_json()` directly.
  Writes now go through `save_kea_config()`, which backs up first, prunes to the
  most recent 100 per config, and **refuses the write** if the backup fails.
- **Restore no longer fails on a normal packaged Kea install.** It used
  `shutil.copy2()`, which chmods the destination — and chmod needs *ownership*,
  which EZ-KEA does not have over a `_kea`-owned `/etc/kea/kea-dhcp4.conf`. It
  raised `EPERM` *after* writing the contents, so the restore silently succeeded
  while reporting HTTP 500. Now uses `copyfile()`, leaving ownership and mode to
  whoever set up Kea.
- **Saving Global Settings no longer writes a config Kea refuses to load.** It
  emitted `output_options` (underscore) alongside the correct `output-options`,
  which Kea rejects as a duplicate, and injected an empty
  `host-reservation-identifiers: []`, which Kea rejects outright. One Save click
  left the live config unloadable.
- **Saving Global Settings no longer silently demotes the other protocol to the
  sandbox.** On the first save the settings file was seeded from the `./data`
  defaults, so saving the DHCPv4 form pinned DHCPv6 to a sandbox path — and
  writing the file makes discovery stop looking for the running daemon. Every
  later DHCPv6 edit then went to a file `kea-dhcp6` never reads, with no warning.
  The version not being saved is now seeded from what discovery actually
  resolved.
- **The control-socket reload strategy works against a stock ISC config.** Those
  configs use a bare relative `socket-name` (`kea4-ctrl-socket`), which Kea
  resolves against `/var/run/kea`; EZ-KEA passed it to `connect()` verbatim, so
  it looked in its own working directory. This mattered doubly because Kea 3.2
  ships no `keactrl`, leaving the control socket as the only reload path.
- **The DHCPv6 Pools page shows standalone subnets.** Kea writes a plain
  single-subnet v6 server as a top-level `Dhcp6.subnet6[]`, and the page read
  only `shared-networks` — so such a server displayed as "No IPv6 Shared
  Networks Configured", hiding live subnets and inviting the operator to
  recreate config that already existed. Standalone v6 subnets can now be
  listed, created, deleted, and given options, matching DHCPv4.
- **An unreadable Kea config now explains itself instead of returning a 500.**
  `load_json()` handled missing and corrupt files but not `PermissionError`,
  which is the *normal* first-run state against packaged Kea (`/etc/kea` is 0750
  `_kea:_kea`). It now raises `ConfigAccessError`, rendered as a 503 naming the
  file and the group fix, and the log indexer no longer logs a traceback every
  60 seconds. It deliberately does **not** fall back to the empty skeleton —
  that would show a real server as having no subnets, and the next save would
  overwrite the operator's config with it.

### Removed

- `jsonify==0.5` from `requirements.txt` — an abandoned no-op package unrelated
  to Flask's `jsonify`, imported nowhere, with no wheel on PyPI, so it was built
  from source during the first command every install runs.

### Changed

- **Commercial licensing now states a price.** $500 a year for a single
  deployment — one production install, in one environment, run by one
  organization — with volume licensing quoted for anyone running more than
  one. The README, the in-app Licensing page, and the unlicensed footer note
  and banner all said "commercial use requires a license" without naming a
  number, so the only way to learn the price was to send an email. No licensing
  behaviour changed: nothing is gated, blocked, or expired, and the free
  noncommercial terms are exactly as they were.

## [0.9.0] — 2026-07-31

First tagged release. EZ-KEA has been public since 2026-07-29; this puts a
version on it so an install can be identified.

### Added

- **Kea 3.x support.** Kea 3.0 renamed the singular `control-socket` object to
  a `control-sockets` list. EZ-KEA now reads either spelling, and probes
  `kea-dhcp4 -v` to decide which one to write, so a generated config is
  accepted by the version actually installed. Configs written for Kea 2.x keep
  working untouched.
- **Control-socket reload strategy.** Sends `config-reload` down the daemon's
  own command socket and reports whether the reload succeeded. This is ISC's
  recommended path now that the Control Agent is gone, and it is the only one
  that works on Kea 3.2 installed from ISC's packages, which ship no `keactrl`
  at all. Selectable in Global Settings alongside `keactrl` and Docker SIGHUP.
- **Full-history log search** backed by a SQLite index, rather than tailing.
- **A Kea 3.2.0 testbed target** (`testbed/Dockerfile.kea-3.2`, ISC's own
  packages from Cloudsmith) next to the existing Ubuntu 2.0.2 one. Both build
  the same testbed, so `.env.testbed` and `test_suite.sh` work against either
  unchanged.

### Fixed

- HA peer status no longer breaks on Kea 3.x. It looked up the control socket
  by the pre-3.0 key name only, so on a 3.x config it found nothing and
  reported the peer unreachable.
- The testbed Kea container no longer crash-loops on a stale PID file. As PID 1
  it wrote `1` to its own PID file, saw that PID alive on the next start, and
  aborted with `DHCP4_ALREADY_RUNNING` — which under `restart: unless-stopped`
  only `--force-recreate` cleared.
- `test_suite.sh` runs against either Kea target: it resolves the Kea log path
  at runtime and reads the config on the host, rather than through a
  `docker exec python3` that ISC's 3.x images do not have. This also uncovered
  a test that passed by matching a label in its own capture file rather than a
  delivered DHCP option.

### Changed

- Relicensed to **PolyForm Noncommercial 1.0.0** (source-available; free and
  unlimited for noncommercial use, commercial use needs a paid license). All
  runtime enforcement was removed with it — the previous 100-lease free tier,
  grace period, and write lock are gone. Unlicensed installs show a footer
  note and nothing more.
- Branding standardized on EZ-KEA.

[Unreleased]: https://github.com/fenleytech/ez-kea/compare/v0.9.2...HEAD
[0.9.2]: https://github.com/fenleytech/ez-kea/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/fenleytech/ez-kea/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/fenleytech/ez-kea/releases/tag/v0.9.0
