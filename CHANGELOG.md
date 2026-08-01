# Changelog

Notable changes to EZ-KEA. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While EZ-KEA is on `0.x`, environment variable names, settings keys, and the
on-disk layout under `data/` may still change between releases. Your Kea
configuration is never one of those things — EZ-KEA edits the file Kea already
reads and always backs it up first.

## [Unreleased]

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

[Unreleased]: https://github.com/fenleytech/ez-kea/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/fenleytech/ez-kea/releases/tag/v0.9.0
