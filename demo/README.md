# EZ-Kea public demo

Everything needed to run the demo at <https://demo.ezkea.com> on a fully
synthetic data set, resetting itself on a timer.

| File | Purpose |
| --- | --- |
| `seed_demo.py` | Builds the whole data set: v4/v6 configs, lease CSVs, log files, and a fresh DB with one known demo account. |
| `reset_demo.sh` | Reseeds, clears accumulated backups, restarts the app service. |
| `systemd/ez-kea-demo.service` | Runs the demo on loopback behind a reverse proxy. |
| `systemd/ez-kea-demo-reset.{service,timer}` | Fires `reset_demo.sh` every 30 minutes. |

## Why it resets

EZ-Kea has no read-only role — every DHCP configuration route is
`@login_required` and nothing more, so any visitor who logs in can create and
delete subnets, reservations, and options. Rather than restrict the demo (and
hide the features worth demonstrating), the demo runs the real application
against a sandbox and rebuilds it on a schedule.

The demo account is deliberately **not** an admin, which keeps User
Management, Licensing, and Email Settings out of public reach — a visitor
can't enter a bogus license key or point SMTP at a mail server they control.

## What's in the seed

A fictional mid-size office, sized to stay well under the 100-lease free-tier
limit so the demo shows the product rather than a licensing banner:

- **`corp-campus`** (shared network) — `10.20.10.0/24` and `10.20.20.0/24`
- **`voice-vlan30`** (shared network) — `10.20.30.0/24`, with TFTP and TR-069
  ACS URL options
- **`guest-wifi`** (shared network) — `10.20.40.0/24`, public resolvers, 30-min leases
- **`192.168.50.0/24`** — a standalone management subnet
- IPv6: `corp-campus-v6`, `voice-vlan30-v6`, and `branch-pd-v6` with a
  `2001:db8:4000::/48` prefix-delegation pool
- 62 active DHCPv4 leases, 23 DHCPv6 leases (including two delegated prefixes),
  10 MAC reservations, 4 DUID reservations, and matching daemon logs

Addresses use RFC 3849 (`2001:db8::/32`) and RFC 1918 space, and every MAC,
DUID, and hostname is generated. No real network's inventory appears anywhere.

## Deploying

```bash
# 1. Create the service account and lay down the code
sudo useradd --system --home /srv/ez-kea-demo --shell /usr/sbin/nologin ezkea
sudo git clone https://github.com/fenleytech/ez-kea.git /srv/ez-kea-demo
cd /srv/ez-kea-demo
sudo python3 -m venv venv
sudo ./venv/bin/pip install -r requirements.txt

# 2. Generate the secret key the service reads
sudo install -o ezkea -g ezkea -m 0600 /dev/null /etc/ez-kea-demo.env
echo "SECRET_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))')" \
    | sudo tee -a /etc/ez-kea-demo.env

# 3. Seed the data set for the first time
sudo ./venv/bin/python demo/seed_demo.py --target /srv/ez-kea-demo/data
sudo chown -R ezkea:ezkea /srv/ez-kea-demo/data

# 4. Install the units
sudo cp demo/systemd/*.service demo/systemd/*.timer /etc/systemd/system/
sudo chmod +x demo/reset_demo.sh
sudo systemctl daemon-reload
sudo systemctl enable --now ez-kea-demo.service ez-kea-demo-reset.timer
```

Then point your reverse proxy at `127.0.0.1:8080` and terminate TLS there.

Verify the timer with `systemctl list-timers ez-kea-demo-reset.timer`, and
force a reset any time with `sudo systemctl start ez-kea-demo-reset.service`.

## Changing the demo credentials

The published credentials are `demo` / `demo`. To change them, edit
`DEMO_USER` / `DEMO_PASSWORD` in `systemd/ez-kea-demo-reset.service`, run a
reset, and update the README's Live Demo section to match — the account is
recreated from those values on every reset, so changing them anywhere else
gets overwritten within 30 minutes.
