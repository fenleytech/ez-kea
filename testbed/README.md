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

## Choosing a Kea version

Two targets are available. Both build the *same* testbed — same container name,
same volume mounts, same client containers — so everything below applies to
either without changes.

| Target | Dockerfile | Kea | Packages |
| --- | --- | --- | --- |
| **default** | `Dockerfile.kea` | 2.0.2 | Ubuntu 22.04's `kea-dhcp4-server` |
| **3.2** | `Dockerfile.kea-3.2` | 3.2.0 | ISC's own `isc-kea-dhcp4`/`isc-kea-dhcp6` from Cloudsmith |

```bash
# default (Kea 2.x)
docker compose -f testbed/docker-compose.yml up -d

# Kea 3.2.0
KEA_DOCKERFILE=Dockerfile.kea-3.2 docker compose -f testbed/docker-compose.yml up -d --build
```

Both targets produce a container named `kea-testbed-kea-1` with the same mounts,
so `.env.testbed` and `test_suite.sh` work against either unchanged. Switching
targets rebuilds the same service — bring the old one down first
(`docker compose -f testbed/docker-compose.yml down`) so you aren't running a
stale container against a freshly built image.

**Why the 3.2 target matters.** Kea 3.0 renamed the singular `control-socket`
object to a `control-sockets` list, and 3.2 dropped the Control Agent. Ubuntu
ships no 3.x package, so without this target nothing catches EZ-KEA emitting
config a current Kea rejects. EZ-KEA picks the syntax by probing `kea-dhcp4 -v`
(`ez_kea/core/kea_version.py`), and this is the only place that probe meets a
real 3.x binary.

### Kea 3.x behaves differently in ways that will bite you

All four of these were found by actually running this target, not from the docs:

1. **`keactrl` does not exist in ISC's 3.2 packages.** Not in `isc-kea-common`,
   not anywhere on the filesystem — Ubuntu's 2.x `kea-common` does ship it at
   `/usr/sbin/keactrl`. EZ-KEA's default `keactrl reload` strategy therefore
   cannot work here. Use the **Docker container SIGHUP** strategy (see the
   reload note further down); it is not optional for this target.
   Note `keactrl` is a *different* tool from the removed Control Agent — it is
   still in the 3.2 source tree, ISC's packaging just doesn't install it.
2. **Logger `output` must be under `/var/log/kea`.** Kea 3.x rejects anything
   else outright (`invalid path in 'output' ... supported path is
   '/var/log/kea'`). The 2.x example config's `/var/log/kea-dhcp4.log` fails.
3. **The control-socket directory must be no more permissive than 750.**
   `Dockerfile.kea` chmods `/var/run/kea` to 777, which 3.x refuses; the 3.2
   target uses 750 deliberately.
4. **The singular `control-socket` is still accepted** by 3.2.0 — verified by
   syntax-checking both spellings against the real binary. It is a
   backward-compatibility alias, not something to rely on long-term.

### Seeding a config for the 3.2 target

`kea-dhcp4.conf.kea3.example` is the 3.x counterpart to
`kea-dhcp4.conf.example`, differing only in the two points above
(`control-sockets`, and a `/var/log/kea/` logger path):

```bash
mkdir -p data/var/log/kea    # may need the container: see below
cp data/etc/kea/kea-dhcp4.conf.kea3.example data/etc/kea/kea-dhcp4.conf
```

`data/var/log` is created root-owned by the container, so if that `mkdir`
fails, make it from inside one:

```bash
docker run --rm -v "$PWD/data/var/log:/var/log" \
  $(docker compose -f docker-compose.yml config --images | head -1) \
  sh -c 'mkdir -p /var/log/kea && chmod 750 /var/log/kea'
```

Because the log lives one directory deeper on this target, the in-container
log path differs from the 2.x default:

```bash
DHCP_LOG_FILE_IN_CONTAINER=/var/log/kea/kea-dhcp4.log
DHCP_LOG_FILE=./testbed/data/var/log/kea/kea-dhcp4.log
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
