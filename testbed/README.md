# Kea DHCP Docker Testbed

This isolated Docker environment enables safe testing of Kea DHCP configurations, simulating client requests across different simulated VLANs, and viewing leases without interfering with your local development machine's actual network.

## Quick start

From the repo root, the one-command path (`.env.testbed` is committed and already has everything below filled in for this testbed):

```bash
docker compose -f testbed/docker-compose.yml up -d
bash start_testbed.sh
```

`start_testbed.sh` sources `.env.testbed` and starts EZ-KEA pointed at the testbed. Open the app and go to Global Settings — the Docker-deployment fields (in-container paths, reload strategy) are already populated; "Apply Changes" reloads the real containerized Kea via SIGHUP.

## Manual setup

1. Copy the example configuration to act as your base config (or let EZ-KEA generate it):
   ```bash
   cp data/etc/kea/kea-dhcp4.conf.example data/etc/kea/kea-dhcp4.conf
   ```

   **Note:** the example config includes a default `interfaces-config` (`eth0`, `eth1`, `eth2` — the three simulated VLAN interfaces this compose file attaches to the `kea` container). If you write your own config from scratch instead of copying the example, remember to set `interfaces-config` yourself — the base Kea container otherwise starts with **no interfaces configured at all** and cannot answer DHCP traffic on any VLAN until you do (this cost the original audit real time to discover).

2. Start the testbed:
   ```bash
   docker compose up -d
   ```

## Integration with local EZ-KEA

To have your local instance of EZ-KEA interact with this dockerized Kea server instead of a bare-metal local installation, point it at these files (see `.env.testbed` at the repo root, or set the equivalent env vars / Global Settings fields yourself):

```bash
# Host paths -- what EZ-KEA itself reads/writes
DHCP_CONFIG_FILE=./testbed/data/etc/kea/kea-dhcp4.conf
DHCP_LEASES_FILE=./testbed/data/var/lib/kea/kea-leases4.csv
DHCP_LOG_FILE=./testbed/data/var/log/kea-dhcp4.log
BACKUP_DIR=./testbed/data/backups/
```

And to allow EZ-KEA to syntax-check and reload the dockerized Kea process, point the Kea commands at `docker exec`:

```bash
KEA_DHCP4_CMD=docker exec kea-testbed-kea-1 kea-dhcp4
KEA_CTRL_CMD=docker exec kea-testbed-kea-1 keactrl
```

**This alone is not enough** — `docker exec ... kea-dhcp4 -t <path>` runs inside the container's own
filesystem namespace, where the *host* path above does not exist (the volume mount exposes the same
file at a different in-container path). EZ-KEA has an explicit "in-container path" setting for exactly
this (Global Settings → Docker Deployment, or the equivalent env vars):

```bash
DHCP_CONFIG_FILE_IN_CONTAINER=/etc/kea/kea-dhcp4.conf
DHCP_LOG_FILE_IN_CONTAINER=/var/log/kea-dhcp4.log
```

*Note on reload: `keactrl` requires a configuration file at `/etc/kea/keactrl.conf`, which isn't
mounted into this testbed's container by default (see `Dockerfile.kea`) — so `keactrl reload` fails
here even once the path issue above is fixed. EZ-KEA supports an explicit alternate reload strategy for
this: set "Reload Strategy" to **Docker container SIGHUP** in Global Settings (or `KEA_RELOAD_STRATEGY=sighup`
+ `KEA_DOCKER_CONTAINER=kea-testbed-kea-1`), which runs `docker kill -s HUP kea-testbed-kea-1` instead of
`keactrl reload`. This is never inferred automatically — it's an explicit choice, since guessing wrong
here is worse than requiring the extra setting.*

## Simulating DHCP Client Requests

We have created two client containers attached to `vlan10` and `vlan20` respectively.
To trigger DHCP DISCOVER packets from these clients and view the resulting leases, run:

```bash
./run_clients.sh
```

This will run `udhcpc` on the clients and then print out the `kea-leases4.csv` file. You can change the MAC address of the clients by modifying `docker-compose.yml` to test specific MAC reservations in EZ-KEA.
