<p align="center">
  <img src="static/icons/icon-192.png" width="96" alt="EZ-Kea logo">
</p>

<h1 align="center">EZ-Kea</h1>

<p align="center">
  A zero-config web interface for ISC Kea DHCP. Point it at your server and it finds your config.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+">
  <a href="https://kea.fenleytech.com"><img src="https://img.shields.io/badge/demo-live-brightgreen.svg" alt="Live demo"></a>
  <img src="https://img.shields.io/badge/tests-231%20passing-brightgreen.svg" alt="231 tests">
</p>

![EZ-Kea managing DHCPv4 shared networks and pools](docs/images/pools.png)

EZ-Kea gives ISC Kea a web UI without asking you to restructure anything. It
scans `/proc` for running `kea-dhcp4`/`kea-dhcp6` processes, reads the config
path each daemon was actually launched with, and edits that file in place. If
Kea isn't installed, it builds a sandbox under `./data/` and runs in demo mode
so you can model a network offline.

## Live demo

**<https://kea.fenleytech.com>** — log in with `demo` / `demo`.

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

The source in this repository is MIT licensed. The application it builds is
open-core, and it's worth knowing where the line sits before you deploy it:

- **Free tier** — every feature, up to **100 active DHCP leases**.
- Past 100 leases, a banner appears and a **7-day grace period** starts.
- After the grace period, **configuration changes are blocked** until a
  commercial license key is entered. Existing config stays readable and Kea
  keeps serving DHCP — EZ-Kea never stops your DHCP server, it only stops
  editing it.

For a commercial license, email **<sales@ezkea.com>**. Full details in
[Licensing](https://github.com/fenleytech/ez-kea/wiki/Licensing).

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
| [Licensing](https://github.com/fenleytech/ez-kea/wiki/Licensing) | Free tier, grace period, license keys |

## Support

- **Bugs and feature requests** — [GitHub Issues](https://github.com/fenleytech/ez-kea/issues)
- **Commercial licensing** — <sales@ezkea.com>

## Contributing

Contributions are welcome. The test suite runs with no Kea installation and no
network access:

```bash
pip install -r requirements.txt
python -m pytest
```

There's also a containerized ISC Kea testbed that boots a real DHCP server on
two virtual VLANs and drives actual DHCP transactions against it:

```bash
cd testbed && bash test_suite.sh
```

See [testbed/README.md](testbed/README.md) and
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE). Note the free-tier lease limit described under
[Licensing](#licensing) above.
