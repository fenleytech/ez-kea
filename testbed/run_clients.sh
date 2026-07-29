#!/bin/bash
# Script to easily test client DHCP requests in the testbed

echo "============================================="
echo "Triggering DHCP DISCOVER on client-vlan10..."
echo "MAC: 00:11:22:33:44:55"
echo "============================================="
docker exec kea-testbed-client-vlan10-1 sh -c 'udhcpc -i eth0 -f -q -n || echo "DHCP Timeout"'

echo ""
echo "============================================="
echo "Triggering DHCP DISCOVER on client-vlan20..."
echo "MAC: aa:bb:cc:dd:ee:ff"
echo "============================================="
docker exec kea-testbed-client-vlan20-1 sh -c 'udhcpc -i eth0 -f -q -n || echo "DHCP Timeout"'

echo ""
echo "============================================="
echo "Current Leases (kea-leases4.csv):"
echo "============================================="
cat data/var/lib/kea/kea-leases4.csv 2>/dev/null || echo "No leases file found yet."
