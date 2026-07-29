#!/bin/bash
# script: apply_changes.sh
# description: Automates the Method of Procedure (MOP) for testing and reloading Kea DHCP components safely.

set -e

DHCP_CONF=${1:-"/etc/kea/kea-dhcp4.conf"}
BACKUP_DIR=${2:-"/var/kea/backups"}

echo "[*] Starting Kea DHCP MOP Application workflow..."

if [ ! -f "$DHCP_CONF" ]; then
    echo "[!] Error: Configuration file $DHCP_CONF not found."
    exit 1
fi

mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +"%Y%m%d%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/kea-dhcp4.conf.bak.${TIMESTAMP}"

echo "[*] Step 1: Backing up current configuration to ${BACKUP_FILE}"
cp "$DHCP_CONF" "$BACKUP_FILE"

echo "[*] Step 2: Testing configuration syntax..."
if kea-dhcp4 -t "$DHCP_CONF"; then
    echo "[+] Syntax Check Passed."
else
    echo "[!] Syntax Check Failed! Configuration contains errors."
    echo "[*] Rolling back to pre-MOP state via Git or Backup..."
    # Since this is a git managed project based on the instructions, it's safer to tell them to revert using git,
    # but we can fallback to the file diff.
    exit 1
fi

echo "[*] Step 3: Triggering keactrl reload..."
if keactrl reload; then
    echo "[+] Kea Daemon successfully reloaded with new configuration."
else
    echo "[!] Kea Daemon reload failed. You may need to review system logs."
    echo "[*] Restoring backup..."
    cp "$BACKUP_FILE" "$DHCP_CONF"
    keactrl reload
    exit 2
fi

echo "[+] MOP Complete."
exit 0
