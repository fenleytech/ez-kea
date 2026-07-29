"""
ez_kea/core/ha_manager.py

Manages ISC-Kea's "High Availability" hook (libdhcp_ha.so) inside a
Dhcp4/Dhcp6 config's hooks-libraries[] list. HA lets two (or three) Kea
servers share lease state over HTTP and fail over automatically -- see the
Kea ARM's "High Availability" chapter. The hook's own config lives entirely
inside the DHCP daemon's config file (no separate daemon to manage), which
is exactly the kind of thing EZ-Kea already edits directly.

Note this only manages the hook's parameters block. It does NOT configure
the Kea Control Agent that peers actually talk to over HTTP -- that's a
separate daemon/config file outside EZ-Kea's current scope. The peer "url"
fields entered here must match wherever each peer's own Control Agent is
listening.
"""
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

HA_LIBRARY_BASENAME = "libdhcp_ha.so"

# Debian/Ubuntu ISC package path. RPM-based installs typically use
# /usr/lib/kea/hooks/libdhcp_ha.so instead -- surfaced as an editable field
# in the UI rather than guessed, since getting it wrong just means the hook
# silently fails to load.
DEFAULT_HA_LIBRARY_PATH = "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_ha.so"

HA_MODES = ("hot-standby", "load-balancing", "passive-backup")
HA_ROLES = ("primary", "secondary", "standby", "backup")

_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def find_ha_hook(config: Dict[str, Any], dhcp_key: str = "Dhcp4") -> Optional[Dict[str, Any]]:
    """Return the hooks-libraries[] entry for the HA hook, or None if HA isn't configured."""
    for hook in config.get(dhcp_key, {}).get("hooks-libraries", []):
        if os.path.basename(hook.get("library", "")) == HA_LIBRARY_BASENAME:
            return hook
    return None


def get_ha_params(config: Dict[str, Any], dhcp_key: str = "Dhcp4") -> Optional[Dict[str, Any]]:
    """Return the high-availability[0] parameters dict for the HA hook, or None."""
    hook = find_ha_hook(config, dhcp_key)
    if not hook:
        return None
    ha_list = hook.get("parameters", {}).get("high-availability", [])
    return ha_list[0] if ha_list else None


def set_ha_config(config: Dict[str, Any], library_path: str, ha_params: Dict[str, Any], dhcp_key: str = "Dhcp4") -> None:
    """
    Insert or replace the HA hook entry in hooks-libraries[], leaving any
    other configured hooks untouched.
    """
    dhcp_section = config.setdefault(dhcp_key, {})
    hooks = [
        h for h in dhcp_section.get("hooks-libraries", [])
        if os.path.basename(h.get("library", "")) != HA_LIBRARY_BASENAME
    ]
    hooks.append({
        "library": library_path,
        "parameters": {"high-availability": [ha_params]},
    })
    dhcp_section["hooks-libraries"] = hooks


def remove_ha_config(config: Dict[str, Any], dhcp_key: str = "Dhcp4") -> None:
    """Remove the HA hook entry from hooks-libraries[], leaving other hooks untouched."""
    dhcp_section = config.get(dhcp_key)
    if dhcp_section and "hooks-libraries" in dhcp_section:
        dhcp_section["hooks-libraries"] = [
            h for h in dhcp_section["hooks-libraries"]
            if os.path.basename(h.get("library", "")) != HA_LIBRARY_BASENAME
        ]


def _parse_positive_int(form: Any, field: str, label: str, errors: List[str], minimum: int = 0) -> Optional[int]:
    raw = (form.get(field) or "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        errors.append(f"{label} must be a whole number.")
        return None
    if value < minimum:
        errors.append(f"{label} must be >= {minimum}.")
        return None
    return value


def parse_ha_form(form: Any) -> Tuple[Optional[Tuple[str, Dict[str, Any]]], List[str]]:
    """
    Parse a submitted HA form into (library_path, ha_params) plus a list of
    validation errors. On any error, the first element is None -- callers
    should not save a partially-valid config.

    Expects (all optional unless noted):
      this-server-name, ha-mode, ha-library-path,
      heartbeat-delay, max-response-delay, max-ack-delay, max-unacked-clients,
      peer-name[], peer-url[], peer-role[], peer-autofailover[] (parallel lists,
      one entry per peer row; auto-failover is "yes"/"no", not a checkbox, so
      the lists stay in lockstep even when a value is "unset").
    """
    errors: List[str] = []

    library_path = (form.get("ha-library-path") or "").strip() or DEFAULT_HA_LIBRARY_PATH
    if not library_path.endswith(".so"):
        errors.append("HA hook library path must be a path to a .so file.")

    this_server_name = (form.get("this-server-name") or "").strip()
    if not this_server_name:
        errors.append("'This Server Name' is required.")
    elif not _NAME_RE.match(this_server_name):
        errors.append("'This Server Name' may only contain letters, digits, '.', '_', and '-'.")

    mode = (form.get("ha-mode") or "").strip()
    if mode not in HA_MODES:
        errors.append(f"Mode must be one of: {', '.join(HA_MODES)}.")

    heartbeat_delay = _parse_positive_int(form, "heartbeat-delay", "Heartbeat Delay", errors, minimum=0)
    max_response_delay = _parse_positive_int(form, "max-response-delay", "Max Response Delay", errors, minimum=1)
    max_ack_delay = _parse_positive_int(form, "max-ack-delay", "Max Ack Delay", errors, minimum=0)
    max_unacked_clients = _parse_positive_int(form, "max-unacked-clients", "Max Unacked Clients", errors, minimum=0)

    names = form.getlist("peer-name[]")
    urls = form.getlist("peer-url[]")
    roles = form.getlist("peer-role[]")
    autofailovers = form.getlist("peer-autofailover[]")

    peers: List[Dict[str, Any]] = []
    seen_names = set()
    for name, url, role, autofailover in zip(names, urls, roles, autofailovers):
        name = name.strip()
        url = url.strip()
        role = role.strip()
        if not name and not url:
            continue  # blank trailing row from the "add peer" UI

        if not name:
            errors.append("Every peer needs a name.")
            continue
        if not _NAME_RE.match(name):
            errors.append(f"Peer name '{name}' may only contain letters, digits, '.', '_', and '-'.")
            continue
        if name in seen_names:
            errors.append(f"Duplicate peer name '{name}'.")
            continue

        parsed_url = urlparse(url)
        if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:
            errors.append(f"Peer '{name}': URL must be a valid http:// or https:// URL.")
            continue

        if role not in HA_ROLES:
            errors.append(f"Peer '{name}': role must be one of {', '.join(HA_ROLES)}.")
            continue

        seen_names.add(name)
        peers.append({
            "name": name,
            "url": url,
            "role": role,
            "auto-failover": autofailover == "yes",
        })

    if this_server_name and this_server_name not in seen_names:
        errors.append(f"'This Server Name' ('{this_server_name}') must match the name of one of the peers below.")

    if len(peers) < 2:
        errors.append("At least two peers are required to configure HA.")

    primary_like = [p for p in peers if p["role"] in ("primary", "standby", "secondary")]
    if mode in ("hot-standby", "load-balancing") and len(primary_like) != 2:
        errors.append(
            f"Mode '{mode}' requires exactly two peers with role primary/standby/secondary "
            f"(found {len(primary_like)}); any additional peers must use role 'backup'."
        )

    if errors:
        return None, errors

    ha_params: Dict[str, Any] = {
        "this-server-name": this_server_name,
        "mode": mode,
        "heartbeat-delay": heartbeat_delay if heartbeat_delay is not None else 10000,
        "max-response-delay": max_response_delay if max_response_delay is not None else 60000,
        "max-ack-delay": max_ack_delay if max_ack_delay is not None else 10000,
        "max-unacked-clients": max_unacked_clients if max_unacked_clients is not None else 0,
        "peers": peers,
    }
    return (library_path, ha_params), errors
