#!/bin/sh
# Shared entrypoint for both testbed Kea targets.
#
# Exists because Kea refuses to start when it finds a PID file naming a live
# process, and in a container that check is unwinnable: Kea is PID 1, writes
# "1" to its PID file, and on the next start inside the same container
# filesystem sees PID 1 alive -- itself -- and aborts with
# DHCP4_ALREADY_RUNNING. Combined with `restart: unless-stopped` that is a
# permanent crash loop, which is exactly how this testbed sat broken for three
# weeks. `docker compose restart` reuses the container filesystem, so it
# reproduces every time; only --force-recreate cleared it.
#
# A PID file present at container start is stale by definition: a running Kea
# would mean the container was already up, in which case we would not be here.
set -e

rm -f /run/kea/*.pid /var/run/kea/*.pid 2>/dev/null || true

# Kea 3.x rejects any logger `output` path outside /var/log/kea, and /var/log
# is bind-mounted from the host, so the directory cannot be baked into the
# image -- create it at start instead. 755 rather than 750 deliberately: the
# host user has to be able to read the log through the bind mount, which is
# how EZ-KEA's own /logs viewer reaches it in this testbed.
mkdir -p /var/log/kea
chmod 755 /var/log/kea

# Kea 3.x creates its log file mode 0640 root:root, which the unprivileged host
# user cannot read through the bind mount -- that would blind EZ-KEA's own
# /logs viewer against this testbed. Pre-create the files at 0644 so Kea opens
# an existing file for append instead of creating one with its own mode.
for log_file in /var/log/kea/kea-dhcp4.log /var/log/kea/kea-dhcp6.log; do
    [ -e "$log_file" ] || : > "$log_file"
    chmod 644 "$log_file" 2>/dev/null || true
done

# exec so Kea becomes PID 1 and receives signals directly -- the SIGHUP reload
# strategy (`docker kill -s HUP kea-testbed-kea-1`) depends on this.
exec "$@"
