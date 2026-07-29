# Contributing to EZ-Kea

Thanks for taking the time. Bug reports, reproductions, and pull requests are
all welcome.

## Getting set up

```bash
git clone https://github.com/fenleytech/ez-kea.git
cd ez-kea
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m pytest
```

Python 3.10 or newer is required — the codebase uses PEP 604 (`X | None`)
annotations that are evaluated at runtime.

The tests need neither a Kea installation nor network access; they work
against temporary config files and an in-memory database.

## Running the app

```bash
python3 app.py
```

Binds `127.0.0.1:8080` and signs in with `admin` / `changeme` on a fresh
database. With no Kea present it creates a sandbox under `./data/` and runs in
DEMO mode, which is the easiest way to work on UI changes.

To develop against a realistic data set, seed the demo fixtures:

```bash
python3 demo/seed_demo.py --target ./data
```

That gives you populated subnets, reservations, leases, and logs to work with.
See [demo/README.md](demo/README.md).

## Testing against real Kea

`testbed/` boots a containerized ISC Kea on two virtual VLANs and drives real
DHCP transactions through it — pools, reservations, option delivery, and pool
exhaustion:

```bash
cd testbed && bash test_suite.sh
```

## Pull requests

- Add or update tests for behaviour changes; the suite is currently 231 tests
  and shouldn't go backwards.
- Match the surrounding style. The codebase leans on explanatory comments for
  non-obvious decisions rather than restating what the code does.
- Keep DHCPv4 and DHCPv6 in step. They're deliberately separate code paths
  (`routes/dhcp4.py` and `routes/dhcp6.py`), so a fix to one is usually needed
  in the other.
- Note anything that changes public behaviour so the README and wiki can be
  updated to match.

## Reporting bugs

Open an issue with the EZ-Kea mode (LIVE or DEMO), your Kea version if
relevant, what you expected, and what happened. Config snippets help — please
scrub real MAC addresses and hostnames first.

For security issues, see [SECURITY.md](SECURITY.md) rather than opening a
public issue.
