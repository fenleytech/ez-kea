# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
ez_kea/core/ha_manager.py

Manages ISC-Kea's "High Availability" hook (libdhcp_ha.so) inside a
Dhcp4/Dhcp6 config's hooks-libraries[] list. HA lets two (or three) Kea
servers share lease state over HTTP and fail over automatically -- see the
Kea ARM's "High Availability" chapter and ISC's "Kea HA Quickstart Guide".

What a working HA setup needs, and what this module writes:

- **libdhcp_lease_cmds.so, loaded before libdhcp_ha.so.** HA syncs leases by
  calling lease4-get-page / lease6-get-page on the partner, which only exist
  when lease_cmds is loaded. Without it both servers sit in SYNCING/WAITING
  forever and serve no clients at all (reproduced on Kea 3.2.1, 2026-11-10).
- **A `multi-threading` block with a dedicated HTTP listener.** Each server's
  HA hook listens on its own peer `url` (conventionally port 8001) and the
  partner talks to that. No Kea Control Agent is involved: it was deprecated
  in 3.0 and is gone in 3.2. On an old Kea without core multi-threading the
  block is ignored and peers talk through the Control Agent instead.
- **IP literals in peer URLs.** Kea's config check accepts a hostname, but
  the HA hook then refuses to load ("Failed to convert string to address"),
  which fails the reload.
- **For load-balancing, every pool split between the two servers** with the
  HA_<server-name> client classes. Unsplit pools hand the same address to
  two clients whenever the HA link drops. sync_lb_pool_split() keeps that
  true across every config write.

Parameters EZ-KEA has no field for (TLS, basic auth, extra relationships,
max-rejected-lease-updates, ...) are preserved when the form is saved.
"""
import copy
import ipaddress
import os
import re
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlparse

HA_LIBRARY_BASENAME = "libdhcp_ha.so"
LEASE_CMDS_BASENAME = "libdhcp_lease_cmds.so"

# Hook load order per the Kea ARM: lease_cmds and flex_id before HA, forensic
# logging (legal_log) last.
_MUST_PRECEDE_HA = (LEASE_CMDS_BASENAME, "libdhcp_flex_id.so")
_MUST_FOLLOW_HA = ("libdhcp_legal_log.so",)

# Debian/Ubuntu ISC package path. RPM-based installs typically use
# /usr/lib/kea/hooks/libdhcp_ha.so instead -- surfaced as an editable field
# in the UI rather than guessed, since getting it wrong just means the hook
# silently fails to load.
DEFAULT_HA_LIBRARY_PATH = "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_ha.so"

HA_MODES = ("hot-standby", "load-balancing", "passive-backup")
HA_ROLES = ("primary", "secondary", "standby", "backup")

# The partner role each two-server mode requires alongside the primary.
_PARTNER_ROLE = {"hot-standby": "standby", "load-balancing": "secondary"}

# ISC defaults (Kea ARM, HA configuration parameters).
DEFAULT_HEARTBEAT_DELAY = 10000
DEFAULT_MAX_RESPONSE_DELAY = 60000
DEFAULT_MAX_ACK_DELAY = 10000
DEFAULT_MAX_UNACKED_CLIENTS = 10

DEFAULT_HA_MULTI_THREADING = {
    "enable-multi-threading": True,
    "http-dedicated-listener": True,
    "http-listener-threads": 0,
    "http-client-threads": 0,
}

_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")

_SUBNET_KEY = {"Dhcp4": "subnet4", "Dhcp6": "subnet6"}


def _basename(hook: Dict[str, Any]) -> str:
    return os.path.basename(hook.get("library", ""))


def find_ha_hook(config: Dict[str, Any], dhcp_key: str = "Dhcp4") -> Optional[Dict[str, Any]]:
    """Return the hooks-libraries[] entry for the HA hook, or None if HA isn't configured."""
    for hook in config.get(dhcp_key, {}).get("hooks-libraries", []):
        if _basename(hook) == HA_LIBRARY_BASENAME:
            return hook
    return None


def get_ha_params(config: Dict[str, Any], dhcp_key: str = "Dhcp4") -> Optional[Dict[str, Any]]:
    """Return the high-availability[0] parameters dict for the HA hook, or None."""
    hook = find_ha_hook(config, dhcp_key)
    if not hook:
        return None
    ha_list = hook.get("parameters", {}).get("high-availability", [])
    return ha_list[0] if ha_list else None


def _merge_ha_params(old: Optional[Dict[str, Any]], new: Dict[str, Any]) -> Dict[str, Any]:
    """
    Overlay the form-managed keys in `new` onto the existing relationship,
    keeping everything the form has no field for (TLS files, basic auth,
    max-rejected-lease-updates, a hand-tuned multi-threading block, ...).
    Peers are matched by name so per-peer extras survive too; peers missing
    from `new` are dropped, because the form is the full peer list.
    """
    merged = copy.deepcopy(old) if old else {}
    merged.update({k: v for k, v in new.items() if k != "peers"})
    old_peers = {p.get("name"): p for p in (old or {}).get("peers", [])}
    peers = []
    for peer in new.get("peers", []):
        base = copy.deepcopy(old_peers.get(peer["name"], {}))
        base.update(peer)
        peers.append(base)
    merged["peers"] = peers
    merged.setdefault("multi-threading", copy.deepcopy(DEFAULT_HA_MULTI_THREADING))
    return merged


def set_ha_config(config: Dict[str, Any], library_path: str, ha_params: Dict[str, Any], dhcp_key: str = "Dhcp4") -> None:
    """
    Insert or update the HA hook entry in hooks-libraries[], leaving any
    other configured hooks untouched.

    Also makes sure libdhcp_lease_cmds.so is loaded (from the same directory
    as the HA library unless it is already configured) and that HA sits after
    lease_cmds/flex_id and before forensic logging. Additional HA
    relationships (hub-and-spoke) beyond the first are kept as they are.
    """
    dhcp_section = config.setdefault(dhcp_key, {})
    old_hook = find_ha_hook(config, dhcp_key)
    old_list = (old_hook or {}).get("parameters", {}).get("high-availability", [])
    merged = _merge_ha_params(old_list[0] if old_list else None, ha_params)

    hooks = [h for h in dhcp_section.get("hooks-libraries", []) if _basename(h) != HA_LIBRARY_BASENAME]

    if not any(_basename(h) == LEASE_CMDS_BASENAME for h in hooks):
        lease_cmds = {"library": os.path.join(os.path.dirname(library_path), LEASE_CMDS_BASENAME)}
        follow = [i for i, h in enumerate(hooks) if _basename(h) in _MUST_FOLLOW_HA]
        hooks.insert(follow[0] if follow else len(hooks), lease_cmds)

    parameters = copy.deepcopy((old_hook or {}).get("parameters", {}))
    parameters["high-availability"] = [merged] + copy.deepcopy(old_list[1:])
    ha_hook = {"library": library_path, "parameters": parameters}

    precede = [i for i, h in enumerate(hooks) if _basename(h) in _MUST_PRECEDE_HA]
    hooks.insert(precede[-1] + 1 if precede else 0, ha_hook)
    dhcp_section["hooks-libraries"] = hooks


def remove_ha_config(config: Dict[str, Any], dhcp_key: str = "Dhcp4") -> None:
    """
    Remove the HA hook entry from hooks-libraries[], leaving other hooks
    untouched. libdhcp_lease_cmds.so stays: it is harmless on its own and
    other tooling (Stork, scripts) commonly relies on it.
    """
    dhcp_section = config.get(dhcp_key)
    if dhcp_section and "hooks-libraries" in dhcp_section:
        dhcp_section["hooks-libraries"] = [
            h for h in dhcp_section["hooks-libraries"] if _basename(h) != HA_LIBRARY_BASENAME
        ]


def peer_config(config: Dict[str, Any], dhcp_key: str, peer_name: str) -> Optional[Dict[str, Any]]:
    """
    The config the named peer should run: this server's config with only
    `this-server-name` changed, which is what ISC asks for (identical configs
    apart from this-server-name and interfaces). None if HA isn't configured
    or the peer isn't in the list.
    """
    ha = get_ha_params(config, dhcp_key)
    if not ha or peer_name not in {p.get("name") for p in ha.get("peers", [])}:
        return None
    exported = copy.deepcopy(config)
    get_ha_params(exported, dhcp_key)["this-server-name"] = peer_name
    return exported


def _http_control_socket_ports(config: Dict[str, Any], dhcp_key: str) -> List[int]:
    daemon = config.get(dhcp_key, {})
    entries = daemon.get("control-sockets", daemon.get("control-socket"))
    if isinstance(entries, dict):
        entries = [entries]
    ports = []
    for entry in entries or []:
        if isinstance(entry, dict) and entry.get("socket-type") in ("http", "https"):
            try:
                ports.append(int(entry.get("socket-port", 8000)))
            except (TypeError, ValueError):
                pass
    return ports


def validate_ha_against_config(config: Dict[str, Any], ha_params: Dict[str, Any], dhcp_key: str) -> List[str]:
    """
    Checks that need the rest of the config, not just the form. Currently:
    with the dedicated HA listener on, this server's peer URL must not use the
    port of one of its own HTTP control sockets (both would try to bind it).
    """
    errors: List[str] = []
    old = get_ha_params(config, dhcp_key) or {}
    mt = old.get("multi-threading", DEFAULT_HA_MULTI_THREADING)
    if not (mt.get("enable-multi-threading") and mt.get("http-dedicated-listener")):
        return errors
    me = next((p for p in ha_params.get("peers", []) if p["name"] == ha_params.get("this-server-name")), None)
    if me:
        port = urlparse(me["url"]).port or (443 if me["url"].startswith("https") else 80)
        if port in _http_control_socket_ports(config, dhcp_key):
            errors.append(
                f"This server's peer URL uses port {port}, which is also one of its HTTP control sockets. "
                "The HA hook listens on its own peer URL, so pick a different port (8001 is conventional)."
            )
    return errors


# --- Load-balancing pool split ----------------------------------------------

def lb_pool_classes(ha: Optional[Dict[str, Any]]) -> Optional[Tuple[str, str]]:
    """("HA_<primary>", "HA_<secondary>") when `ha` is a load-balancing pair, else None."""
    if not ha or ha.get("mode") != "load-balancing":
        return None
    by_role = {p.get("role"): p.get("name") for p in ha.get("peers", [])}
    if not by_role.get("primary") or not by_role.get("secondary"):
        return None
    return f"HA_{by_role['primary']}", f"HA_{by_role['secondary']}"


def _pool_classes(pool: Dict[str, Any]) -> List[str]:
    if "client-classes" in pool:
        return list(pool.get("client-classes") or [])
    return [pool["client-class"]] if pool.get("client-class") else []


def _is_ha_pool(pool: Dict[str, Any]) -> bool:
    classes = _pool_classes(pool)
    return len(classes) == 1 and classes[0].startswith("HA_")


def _without_classes(pool: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in pool.items() if k not in ("client-class", "client-classes")}


def _with_class(pool: Dict[str, Any], cls: str, legacy: bool) -> Dict[str, Any]:
    out = _without_classes(pool)
    if legacy:
        out["client-class"] = cls
    else:
        out["client-classes"] = [cls]
    return out


def _range_of(pool: Dict[str, Any]):
    text = str(pool.get("pool", "")).strip()
    try:
        if "-" in text:
            start, end = (ipaddress.ip_address(x.strip()) for x in text.split("-", 1))
        else:
            net = ipaddress.ip_network(text, strict=False)
            start, end = net[0], net[-1]
    except ValueError:
        return None
    return (start, end) if start <= end else None


def _prefix_of(pd_pool: Dict[str, Any]):
    try:
        return ipaddress.ip_network(f"{pd_pool['prefix']}/{pd_pool['prefix-len']}", strict=False)
    except (KeyError, ValueError, TypeError):
        return None


def _split_range(pool, classes, legacy):
    rng = _range_of(pool)
    if rng is None or int(rng[1]) - int(rng[0]) < 1:
        return None
    start, end = rng
    mid = start + (int(end) - int(start) + 1) // 2 - 1
    first = _with_class(pool, classes[0], legacy)
    first["pool"] = f"{start} - {mid}"
    second = _with_class(pool, classes[1], legacy)
    second["pool"] = f"{mid + 1} - {end}"
    return [first, second]


def _split_prefix(pd_pool, classes, legacy):
    net = _prefix_of(pd_pool)
    if net is None or net.prefixlen >= int(pd_pool.get("delegated-len", net.prefixlen)):
        return None
    out = []
    for cls, half in zip(classes, net.subnets(prefixlen_diff=1)):
        piece = _with_class(pd_pool, cls, legacy)
        piece["prefix"] = str(half.network_address)
        piece["prefix-len"] = half.prefixlen
        out.append(piece)
    return out


def _merge_ranges(pools):
    """Join HA-classed pools back into unclassed ones (contiguous halves become one pool)."""
    plain = [p for p in pools if not _is_ha_pool(p)]
    halves = sorted((p for p in pools if _is_ha_pool(p)), key=lambda p: (_range_of(p) or (ipaddress.ip_address(0),))[0])
    merged: List[Dict[str, Any]] = []
    for pool in halves:
        pool = _without_classes(pool)
        if merged:
            prev, cur = _range_of(merged[-1]), _range_of(pool)
            same_extras = {k: v for k, v in merged[-1].items() if k != "pool"} == {k: v for k, v in pool.items() if k != "pool"}
            if prev and cur and same_extras and int(prev[1]) + 1 == int(cur[0]):
                merged[-1]["pool"] = f"{prev[0]} - {cur[1]}"
                continue
        merged.append(pool)
    return plain + merged


def _merge_prefixes(pd_pools):
    plain = [p for p in pd_pools if not _is_ha_pool(p)]
    halves = [_without_classes(p) for p in pd_pools if _is_ha_pool(p)]
    merged: List[Dict[str, Any]] = []
    for pool in sorted(halves, key=lambda p: str(_prefix_of(p))):
        net = _prefix_of(pool)
        if merged and net is not None:
            prev = _prefix_of(merged[-1])
            extras = lambda d: {k: v for k, v in d.items() if k not in ("prefix", "prefix-len")}  # noqa: E731
            if (prev is not None and prev.prefixlen == net.prefixlen and prev != net
                    and prev.supernet() == net.supernet() and extras(merged[-1]) == extras(pool)):
                sup = prev.supernet()
                merged[-1]["prefix"], merged[-1]["prefix-len"] = str(sup.network_address), sup.prefixlen
                continue
        merged.append(pool)
    return plain + merged


def _resplit(pools, classes, legacy, splitter, merger, label, warnings):
    if classes is None:
        return merger(pools) if any(_is_ha_pool(p) for p in pools) else pools

    plain = [p for p in pools if not _pool_classes(p)]
    present = {_pool_classes(p)[0] for p in pools if _is_ha_pool(p)}
    for p in pools:
        if _pool_classes(p) and not _is_ha_pool(p):
            warnings.append(
                f"{label}: pool {p.get('pool') or p.get('prefix')} has its own client classes, so EZ-KEA "
                "did not split it between the load-balancing servers. Both may allocate from it."
            )
    if not plain and present == set(classes):
        return pools  # already split for these two servers (possibly by hand); leave it alone

    out = []
    for p in merger(pools):
        if _pool_classes(p):
            out.append(p)
            continue
        pieces = splitter(p, classes, legacy)
        if pieces is None:
            warnings.append(f"{label}: pool {p.get('pool') or p.get('prefix')} is too small to split between the load-balancing servers.")
            out.append(p)
        else:
            out.extend(pieces)
    return out


def _iter_subnets(daemon: Dict[str, Any], dhcp_key: str) -> Iterator[Dict[str, Any]]:
    key = _SUBNET_KEY[dhcp_key]
    for subnet in daemon.get(key, []) or []:
        yield subnet
    for network in daemon.get("shared-networks", []) or []:
        for subnet in network.get(key, []) or []:
            yield subnet


def _uses_legacy_class_key(daemon: Dict[str, Any], dhcp_key: str, probe: Optional[Callable[[], bool]]) -> bool:
    for subnet in _iter_subnets(daemon, dhcp_key):
        for pool in (subnet.get("pools") or []) + (subnet.get("pd-pools") or []):
            if "client-classes" in pool:
                return False
            if "client-class" in pool:
                return True
    return bool(probe()) if probe else False


def sync_lb_pool_split(config: Dict[str, Any], legacy_probe: Optional[Callable[[], bool]] = None) -> List[str]:
    """
    Make every pool match the HA mode, in place, for each daemon section in
    `config`. Returns human-readable warnings for pools it could not handle.

    - Load-balancing: each unclassed pool (and DHCPv6 pd-pool) is split in two
      halves, classed HA_<primary> and HA_<secondary>, so each server only
      allocates from its own half. A pool set already split for the current
      two servers is left exactly as it is, so a hand-tuned split survives.
    - Any other mode, or no HA: halves EZ-KEA split earlier are joined back.

    Pools are written with `client-classes` (Kea 3.0+) unless the config
    already uses the singular `client-class`, or `legacy_probe()` says the
    daemon predates 3.0. The probe is only called when a split is written.
    """
    warnings: List[str] = []
    for dhcp_key in ("Dhcp4", "Dhcp6"):
        daemon = config.get(dhcp_key)
        if not isinstance(daemon, dict):
            continue
        classes = lb_pool_classes(get_ha_params(config, dhcp_key))
        legacy: Optional[bool] = None
        for subnet in _iter_subnets(daemon, dhcp_key):
            label = f"{dhcp_key} subnet {subnet.get('subnet', '?')}"
            for key, splitter, merger in (("pools", _split_range, _merge_ranges), ("pd-pools", _split_prefix, _merge_prefixes)):
                pools = subnet.get(key)
                if not pools:
                    continue
                if classes is not None and legacy is None and any(not _pool_classes(p) for p in pools):
                    legacy = _uses_legacy_class_key(daemon, dhcp_key, legacy_probe)
                subnet[key] = _resplit(pools, classes, bool(legacy), splitter, merger, label, warnings)
    return warnings


def merged_pool_view(pools: List[Dict[str, Any]], kind: str = "pools") -> List[Dict[str, Any]]:
    """Pools as the operator entered them, with any HA load-balancing split joined back up."""
    merger = _merge_prefixes if kind == "pd-pools" else _merge_ranges
    return merger(copy.deepcopy(pools or []))


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
        try:
            ipaddress.ip_address(parsed_url.hostname)
        except ValueError:
            # Kea's own config check accepts a hostname here, but the HA hook
            # then fails to load ("Failed to convert string to address"), so
            # the reload fails. Catch it before it gets that far.
            errors.append(
                f"Peer '{name}': URL must use an IP address, not a hostname "
                f"('{parsed_url.hostname}'). Kea's HA hook does not resolve names."
            )
            continue
        try:
            parsed_url.port
        except ValueError:
            errors.append(f"Peer '{name}': URL has an invalid port.")
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

    # One message for the whole role layout: separate "needs a standby" and
    # "secondary not allowed" errors read as if one peer must be both.
    roles = [p["role"] for p in peers]
    partner = _PARTNER_ROLE.get(mode)
    roles_ok = roles.count("primary") == 1 and all(r in ("primary", partner, "backup") for r in roles)
    if partner:
        roles_ok = roles_ok and roles.count(partner) == 1
    if peers and not roles_ok:
        needed = f"one 'primary' and one '{partner}' peer" if partner else "one 'primary' peer"
        current = ", ".join(f"{p['name']} = {p['role']}" for p in peers)
        errors.append(
            f"Mode '{mode}' needs {needed}; any other peers must be 'backup'. "
            f"Peer roles are currently: {current}."
        )

    heartbeat_delay = DEFAULT_HEARTBEAT_DELAY if heartbeat_delay is None else heartbeat_delay
    max_response_delay = DEFAULT_MAX_RESPONSE_DELAY if max_response_delay is None else max_response_delay
    if max_response_delay <= heartbeat_delay:
        errors.append(
            "Max Response Delay must be greater than Heartbeat Delay (ISC recommends a multiple of it), "
            "otherwise the partner is declared unreachable between two heartbeats."
        )

    if errors:
        return None, errors

    ha_params: Dict[str, Any] = {
        "this-server-name": this_server_name,
        "mode": mode,
        "heartbeat-delay": heartbeat_delay,
        "max-response-delay": max_response_delay,
        "max-ack-delay": max_ack_delay if max_ack_delay is not None else DEFAULT_MAX_ACK_DELAY,
        "max-unacked-clients": max_unacked_clients if max_unacked_clients is not None else DEFAULT_MAX_UNACKED_CLIENTS,
        "peers": peers,
    }
    return (library_path, ha_params), errors
