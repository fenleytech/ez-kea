# EZ-Kea public demo

Everything needed to run the demo at <https://demo.ezkea.com> on a fully
synthetic data set, resetting itself on a timer.

| File | Purpose |
| --- | --- |
| `seed_demo.py` | Builds the whole data set: v4/v6 configs, lease CSVs, log files, and a fresh DB with one known demo account. |
| `reset_demo.sh` | Reseeds, clears accumulated backups, restarts the app service. |
| `systemd/ez-kea-demo.service` | Runs the demo on loopback behind a reverse proxy. |
| `systemd/ez-kea-demo-reset.{service,timer}` | Fires `reset_demo.sh` every 30 minutes. |
| `nginx/demo.ezkea.com.conf` | Reverse proxy, TLS, caching, and rate limits. |
| `nginx/update-cloudflare-ips` | Refreshes Cloudflare ranges for nginx real-IP. |
| `systemd/update-cloudflare-ips.{service,timer}` | Runs that refresh weekly. |

The live deployment runs on a GCP `e2-micro` in `us-central1` behind Cloudflare.

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

A fictional mid-size office, sized to stay well under the 100-lease threshold
where the licensing reminder banner appears, so the demo shows the product
rather than a licensing notice:

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
# 1. Prerequisites. A stock Ubuntu server has python3 but NOT python3-venv,
#    and `python3 -m venv` fails with an ensurepip error without it.
sudo apt-get update
sudo apt-get install -y python3-venv python3-dev nginx

# 2. Create the service account and lay down the code
sudo useradd --system --home /srv/ez-kea-demo --shell /usr/sbin/nologin ezkea
sudo git clone https://github.com/fenleytech/ez-kea.git /srv/ez-kea-demo
cd /srv/ez-kea-demo
sudo python3 -m venv venv
sudo ./venv/bin/pip install -r requirements.txt

# 3. Generate the secret key the service reads
sudo install -o ezkea -g ezkea -m 0600 /dev/null /etc/ez-kea-demo.env
echo "SECRET_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))')" \
    | sudo tee -a /etc/ez-kea-demo.env

# 4. Seed the data set for the first time
sudo ./venv/bin/python demo/seed_demo.py --target /srv/ez-kea-demo/data
sudo chown -R ezkea:ezkea /srv/ez-kea-demo/data

# 5. Install the units
sudo cp demo/systemd/*.service demo/systemd/*.timer /etc/systemd/system/
sudo chmod +x demo/reset_demo.sh
sudo systemctl daemon-reload
sudo systemctl enable --now ez-kea-demo.service ez-kea-demo-reset.timer

# 6. Reverse proxy: origin cert, Cloudflare ranges, then the site config
sudo mkdir -p /etc/nginx/ssl /var/cache/nginx/ezkea
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout /etc/nginx/ssl/demo.ezkea.com.key \
    -out /etc/nginx/ssl/demo.ezkea.com.crt -subj "/CN=demo.ezkea.com"
sudo chmod 600 /etc/nginx/ssl/demo.ezkea.com.key
sudo install -m 0755 demo/nginx/update-cloudflare-ips /usr/local/sbin/
sudo /usr/local/sbin/update-cloudflare-ips
sudo install -m 0644 demo/nginx/demo.ezkea.com.conf /etc/nginx/sites-available/
sudo ln -sf /etc/nginx/sites-available/demo.ezkea.com.conf \
    /etc/nginx/sites-enabled/demo.ezkea.com
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl restart nginx
sudo systemctl enable --now update-cloudflare-ips.timer
```

Verify the timer with `systemctl list-timers ez-kea-demo-reset.timer`, and
force a reset any time with `sudo systemctl start ez-kea-demo-reset.service`.

> On nginx 1.24 (Ubuntu 24.04) the site config uses `listen 443 ssl http2;`.
> The newer standalone `http2 on;` directive only exists from nginx 1.25.1.

## Firewall

The origin only needs to answer Cloudflare. A host firewall enforces that,
which also guarantees nobody can bypass the CDN cache by hitting the IP:

```bash
sudo ufw allow 22/tcp comment SSH          # do this FIRST, before default deny
curl -s https://www.cloudflare.com/ips-v4 -o /tmp/cf4
curl -s https://www.cloudflare.com/ips-v6 -o /tmp/cf6
cat /tmp/cf4 /tmp/cf6 | while read -r cidr; do
    [ -n "$cidr" ] && sudo ufw allow from "$cidr" to any port 80,443 proto tcp
done
sudo ufw default deny incoming
sudo ufw --force enable
```

## Cloudflare settings

- **DNS** — `demo` as a proxied (orange-cloud) A record to the origin IP.
- **SSL/TLS mode** — use **Full**. The site config answers on both 80 and 443
  and deliberately does *not* redirect 80 to 443, because under "Flexible"
  Cloudflare dials port 80 and a redirect there loops forever. Set **Always Use
  HTTPS** at the edge instead.
- To reach **Full (strict)**, replace the self-signed origin cert with a
  Cloudflare Origin CA certificate.

## Keeping inside the GCP free tier

The free tier allows 1 GB/month of North America egress, so the config leans on
Cloudflare to serve as much as possible:

- **Static assets are cached for 30 days** at both nginx and Cloudflare. Flask
  sends `Cache-Control: no-cache` on static files by default, which suppresses
  caching entirely — the site config overrides it with `proxy_hide_header`.
  This is the single biggest lever; verify with
  `curl -sI https://demo.ezkea.com/static/css/styles.css` and look for
  `cf-cache-status: HIT`.
- **The firewall forces all traffic through Cloudflare**, so the cache can't be
  bypassed by requesting the origin IP directly.
- **`robots.txt` disallows everything.** Crawlers are pure egress cost for a
  demo that shouldn't be indexed.
- **Rate and bandwidth limits** — 8 req/s per visitor (burst 24), 16 concurrent
  connections, and `limit_rate 1m` per connection.

GCP has no hard egress cap, so add a billing budget alert as a backstop. Actual
usage is visible in the nginx access log:

```bash
awk '{sum+=$10} END {print sum/1048576 " MiB served"}' \
    /var/log/nginx/demo.ezkea.com.access.log
```

## Changing the demo credentials

The published credentials are `demo` / `demo`, and they live in **two** places
that have to agree:

- `DEMO_USER` / `DEMO_PASSWORD` in `systemd/ez-kea-demo-reset.service` — the
  account `seed_demo.py` actually creates.
- `PUBLIC_DEMO_USERNAME` / `PUBLIC_DEMO_PASSWORD` in
  `systemd/ez-kea-demo.service` — what the login page pre-fills.

To change them, edit both, `systemctl daemon-reload`, run a reset, and update
the README's Live Demo section to match. The account is recreated from the
reset unit's values on every reset, so changing the password anywhere else
gets overwritten within 30 minutes; get the two out of sync and the pre-filled
form simply fails to log in.

## Pre-filled login

`PUBLIC_DEMO=1` in `systemd/ez-kea-demo.service` is what puts those credentials
into the login form. The login screen is still rendered — it's part of what
visitors are there to see — they just don't have to hunt for a password to get
past it. The flag is off by default and is read only from the environment, so
no ordinary install can end up advertising credentials on its login page.
