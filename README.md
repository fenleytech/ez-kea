<p align="center">
  <img src="static/icons/icon-192.png" width="96" alt="EZ-Kea logo">
</p>

<h1 align="center">EZ-Kea</h1>

<p align="center">
  A zero-config web interface for ISC Kea DHCP. Point it at your server and it finds your config.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue.svg" alt="PolyForm Noncommercial License"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+">
  <a href="https://demo.ezkea.com"><img src="https://img.shields.io/badge/demo-live-brightgreen.svg" alt="Live demo"></a>
  <img src="https://img.shields.io/badge/tests-254%20passing-brightgreen.svg" alt="254 tests">
</p>

![EZ-Kea managing DHCPv4 shared networks and pools](docs/images/pools.png)

EZ-Kea gives ISC Kea a web UI without asking you to restructure anything. It
scans `/proc` for running `kea-dhcp4`/`kea-dhcp6` processes, reads the config
path each daemon was actually launched with, and edits that file in place. If
Kea isn't installed, it builds a sandbox under `./data/` and runs in demo mode
so you can model a network offline.

## Live demo

**<https://demo.ezkea.com>** — the login form arrives pre-filled with the demo
account (`demo` / `demo`), so just press Sign In.

It's a shared sandbox running entirely synthetic data, and it resets to a
clean state every 30 minutes, so feel free to create and delete whatever you
like.

## Features

- **Auto-discovery** — finds running Kea daemons and binds to their live config
  files. No paths to configure, though you can override them in the UI.
- **IPv4 and IPv6** — shared networks, standalone subnets, address pools,
  prefix delegation, and per-subnet DHCP options.
- **Reservations** — MAC-based for DHCPv4, DUID-based (address and/or delegated
  prefix) for DHCPv6.
- **High availability** — configure Kea's `libdhcp_ha.so` hook (hot-standby,
  load-balancing, passive-backup) and watch peer state live over the control socket.
- **Safe edits** — back up, restore, syntax-check, and apply configuration from
  the UI, then reload the daemons with `keactrl` (or SIGHUP for Docker installs).
- **Leases and logs** — active DHCPv4/DHCPv6 lease tables and a searchable
  daemon log viewer.
- **Multi-user auth** — accounts with optional TOTP two-factor, recovery codes,
  and SMTP-backed password reset. Admin accounts additionally manage users,
  licensing, and email settings.

Screenshots of the [leases](docs/images/leases.png),
[reservations](docs/images/reservations.png),
[IPv6 pools](docs/images/pools6.png), and [log viewer](docs/images/logs.png)
views. For the full feature list, see the [wiki](https://github.com/fenleytech/ez-kea/wiki).

## Quick start

Requires **Python 3.10+**. ISC Kea is optional — without it, EZ-Kea starts in
demo mode.

```bash
git clone https://github.com/fenleytech/ez-kea.git
cd ez-kea
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open <http://127.0.0.1:8080> and sign in with **`admin`** / **`changeme`**.
You'll be required to change both on first login.

By default EZ-Kea binds to loopback only. To reach it from elsewhere on your
network, set a real secret key and a bind address — it will refuse to start on
a non-loopback address while `SECRET_KEY` is still the default:

```bash
export SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
export HOST=0.0.0.0
python3 app.py
```

Running it as a systemd service, pointing it at a non-standard Kea layout, and
Docker-based Kea deployments are all covered in the
[Installation guide](https://github.com/fenleytech/ez-kea/wiki/Installation).

## Licensing

EZ-Kea is source-available under the
[PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0)
license. In plain terms:

- **Free for noncommercial use** — every feature, no limits, no lease ceiling,
  nothing gated. Homelabs, personal networks, hobby projects, learning and
  experimentation, plus charities, schools, and government bodies.
- **Commercial use requires a license.** If EZ-Kea manages DHCP for a business,
  or you're paid to run it for someone, email **<sales@ezkea.com>**.

Unlicensed installations show a quiet note in the footer. That's the whole of
it — **EZ-Kea never blocks, degrades, or expires anything**. It won't lock you
out of your own DHCP configuration, licensed or not.

The [LICENSE](LICENSE) file governs; the summary above is for orientation, not
a substitute for it. Full details in
[Licensing](https://github.com/fenleytech/ez-kea/wiki/Licensing).

SPDX identifier: `PolyForm-Noncommercial-1.0.0`. Source files carry
`SPDX-License-Identifier` headers, so license scanners and SBOM tooling
identify EZ-Kea correctly. GitHub's sidebar reports "Other" because its
detector only covers OSI-approved and FSF-libre licenses.

## Documentation

The [wiki](https://github.com/fenleytech/ez-kea/wiki) covers the rest:

| | |
| --- | --- |
| [Installation](https://github.com/fenleytech/ez-kea/wiki/Installation) | systemd, reverse proxies, Docker-based Kea |
| [Deployment scenarios](https://github.com/fenleytech/ez-kea/wiki/Deployment-Scenarios) | How discovery picks LIVE vs DEMO mode |
| [Configuration reference](https://github.com/fenleytech/ez-kea/wiki/Configuration-Reference) | Every environment variable and UI override |
| [Security hardening](https://github.com/fenleytech/ez-kea/wiki/Security-Hardening) | Secret keys, 2FA, file permissions, exposure |
| [High availability](https://github.com/fenleytech/ez-kea/wiki/High-Availability) | Setting up the Kea HA hook |
| [Testbed](https://github.com/fenleytech/ez-kea/wiki/Testbed) | Containerized Kea for end-to-end testing |
| [Licensing](https://github.com/fenleytech/ez-kea/wiki/Licensing) | What's free, when you need to pay, license keys |

## Support

- **Bugs and feature requests** — [GitHub Issues](https://github.com/fenleytech/ez-kea/issues)
- **Commercial licensing** — <sales@ezkea.com>

## Development

The test suite runs with no Kea installation and no network access:

```bash
pip install -r requirements.txt
python -m pytest
```

There's also a containerized ISC Kea testbed that boots a real DHCP server on
two virtual VLANs and drives actual DHCP transactions against it — see
[testbed/README.md](testbed/README.md):

```bash
cd testbed && bash test_suite.sh
```

Bug reports and feature requests are genuinely welcome via
[Issues](https://github.com/fenleytech/ez-kea/issues). Pull requests aren't
being accepted — EZ-Kea is also sold under a commercial license, which means
merged code needs a licensing arrangement with each contributor, and that
overhead isn't worth it for a project this size. A good bug report helps more.

## License

[PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0)
— see [LICENSE](LICENSE). Free for noncommercial use; commercial use requires a
license, see [Licensing](#licensing) above.

