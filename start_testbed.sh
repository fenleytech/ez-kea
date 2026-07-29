#!/bin/bash
# start_testbed.sh
# Starts the EZ-Kea frontend with environment pointing at the Docker testbed.
# Run this from the EZ-Kea project root.

set -a          # export all variables
source "$(dirname "$0")/.env.testbed"
set +a

echo "[*] Testbed environment loaded:"
echo "    Config  : $DHCP_CONFIG_FILE"
echo "    Leases  : $DHCP_LEASES_FILE"
echo "    Logs    : $DHCP_LOG_FILE"
echo ""

# Activate venv if present
if [ -f venv/bin/activate ]; then
    source venv/bin/activate
fi

exec python3 app.py
