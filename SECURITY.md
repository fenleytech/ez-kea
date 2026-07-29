# Security Policy

## Reporting a vulnerability

Please report security issues privately to **security@ezkea.com** rather than
opening a public issue. Include steps to reproduce and the impact you think it
has; you'll get an acknowledgement within a few days.

## Scope notes

EZ-Kea edits the configuration of a DHCP server, so a compromise of the web UI
is a compromise of your network's addressing. A few things are worth knowing:

- **`SECRET_KEY` must be set** before exposing EZ-Kea beyond localhost. The app
  refuses to start on a non-loopback bind address while it's still the default,
  and warns loudly otherwise.
- **There is no read-only role.** Any authenticated user can create, modify,
  and delete DHCP configuration. Only user management, licensing, and email
  settings are restricted to admins. Grant accounts accordingly.
- **Run it behind a reverse proxy with TLS.** EZ-Kea serves plain HTTP via
  waitress and does not terminate TLS itself.
- **The default `admin` / `changeme` account** forces a username and password
  change at first login, but the window before that first login is real —
  don't expose a fresh install to an untrusted network.

See [Security hardening](https://github.com/fenleytech/ez-kea/wiki/Security-Hardening)
in the wiki for the full checklist.
