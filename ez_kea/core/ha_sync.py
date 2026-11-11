# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
ez_kea/core/ha_sync.py

Keeps an HA partner's Kea config in step with this server's, so nobody edits
JSON on the second box. Kea's HA hook syncs leases between partners, never
config.

How: Kea 3.x daemons can serve their own control API over HTTP(S) (an `http`
or `https` entry in `control-sockets`; no Control Agent). EZ-KEA talks to each
managed peer's API with basic auth:

  preflight  config-get (the peer's live config: the keys it owns, and the
             config to roll back to), then config-test of the new config
  stage      config-set on every peer, before this server reloads; any
             failure rolls the peers back and nothing is applied anywhere
  commit     after this server reloaded, config-write so each peer's own
             file matches
  status     config-hash-get, compared with the hash recorded at the last push

The pushed config is this server's config with `this-server-name` changed
(ha_manager.peer_config), plus PEER_OWNED_KEYS copied from the peer's live
config. That keeps the peer's interfaces, lease file, logging and, above all,
its own control sockets: a push can never remove the HTTP socket EZ-KEA is
talking through.

The first contact needs that HTTP socket to exist, so each peer is set up
once with bootstrap_script(): a shell script that installs the peer config,
an HTTP control socket and its credential files, and reloads Kea. Kea 3.x
refuses clear-text credentials in the config ("use of clear text 'password'
is NOT SECURE"), so they go in `user-file`/`password-file`.

Settings live in the SystemSetting table (same pattern as the SMTP settings):
  ha_sync_peers   {"Dhcp4": {"<peer>": {"api-url": "..."}}, "Dhcp6": {...}}
  ha_sync_auth    {"username": "...", "password": "...", "ca-file": "..."}
  ha_sync_state   {"Dhcp4": {"<peer>": {"pushed-at", "peer-hash", "local-sha"}}}
"""
import base64
import copy
import hashlib
import ipaddress
import json
import secrets
import shlex
import ssl
import string
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .ha_manager import get_ha_params, peer_config

# Only these commands are ever sent to a peer.
ALLOWED_PEER_COMMANDS = {"config-get", "config-test", "config-set", "config-write", "config-hash-get", "status-get"}

# Keys of the peer's own Dhcp4/Dhcp6 block that a push keeps from the peer's
# live config instead of copying from this server.
PEER_OWNED_KEYS = ("interfaces-config", "control-sockets", "control-socket", "lease-database", "loggers", "server-tag")

DEFAULT_API_USERNAME = "ez-kea"
DEFAULT_API_PORT = 8000
API_REALM = "ez-kea"
CREDENTIAL_DIR = "/etc/kea"
USER_FILE = "ez-kea-api-user"
PASSWORD_FILE = "ez-kea-api-password"

_PEERS_KEY = "ha_sync_peers"
_AUTH_KEY = "ha_sync_auth"
_STATE_KEY = "ha_sync_state"


class PeerApiError(Exception):
    """A peer's control API could not be used. `unreachable` is True when the
    peer could not be contacted at all (as opposed to refusing a request)."""

    def __init__(self, message: str, unreachable: bool = False):
        super().__init__(message)
        self.unreachable = unreachable


# --- settings storage ---------------------------------------------------------

def _get_json_setting(key: str, default: Any) -> Any:
    from ..models import SystemSetting
    row = SystemSetting.query.get(key)
    if row is None or not row.value:
        return copy.deepcopy(default)
    try:
        return json.loads(row.value)
    except json.JSONDecodeError:
        return copy.deepcopy(default)


def _set_json_setting(key: str, value: Any) -> None:
    from ..models import SystemSetting, db
    row = SystemSetting.query.get(key)
    if row is None:
        row = SystemSetting(key=key, value="")
        db.session.add(row)
    row.value = json.dumps(value)
    db.session.commit()


def get_peer_apis(dhcp_key: str) -> Dict[str, Dict[str, str]]:
    return _get_json_setting(_PEERS_KEY, {}).get(dhcp_key, {})


def save_peer_apis(dhcp_key: str, peers: Dict[str, Dict[str, str]]) -> None:
    allp = _get_json_setting(_PEERS_KEY, {})
    allp[dhcp_key] = peers
    _set_json_setting(_PEERS_KEY, allp)


def _new_password() -> str:
    # Alphanumeric only, so it is safe inside the bootstrap script's quoting.
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(32))


def get_auth() -> Dict[str, str]:
    """The credentials EZ-KEA uses on every peer's API, generated on first use."""
    auth = _get_json_setting(_AUTH_KEY, {})
    if not auth.get("username") or not auth.get("password"):
        auth.setdefault("username", DEFAULT_API_USERNAME)
        auth["username"] = auth["username"] or DEFAULT_API_USERNAME
        auth["password"] = auth.get("password") or _new_password()
        auth.setdefault("ca-file", "")
        _set_json_setting(_AUTH_KEY, auth)
    return auth


def save_auth(username: str, password: str, ca_file: str) -> None:
    auth = get_auth()
    auth["username"] = username or auth["username"]
    if password:
        auth["password"] = password
    auth["ca-file"] = ca_file
    _set_json_setting(_AUTH_KEY, auth)


def _get_state(dhcp_key: str) -> Dict[str, Dict[str, str]]:
    return _get_json_setting(_STATE_KEY, {}).get(dhcp_key, {})


def _record_push(dhcp_key: str, peer: str, peer_hash: str, local_sha: str) -> None:
    alls = _get_json_setting(_STATE_KEY, {})
    alls.setdefault(dhcp_key, {})[peer] = {
        "pushed-at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "peer-hash": peer_hash,
        "local-sha": local_sha,
    }
    _set_json_setting(_STATE_KEY, alls)


# --- form parsing -------------------------------------------------------------

def parse_peer_api_form(form: Any, ha_params: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, str]], List[str]]:
    """
    Read the per-peer `peer-api-url[]` column (parallel to `peer-name[]`).
    Blank means "not managed by EZ-KEA". The URL must be http(s)://<IP>:<port>/
    and its port must differ from that peer's HA listener port.
    """
    errors: List[str] = []
    result: Dict[str, Dict[str, str]] = {}
    ha_urls = {p["name"]: p.get("url", "") for p in ha_params.get("peers", [])}
    this = ha_params.get("this-server-name")
    for name, api_url in zip(form.getlist("peer-name[]"), form.getlist("peer-api-url[]")):
        name, api_url = name.strip(), api_url.strip()
        if not name or not api_url or name not in ha_urls:
            continue
        if name == this:
            errors.append(f"Peer '{name}' is this server; leave its Control API URL blank.")
            continue
        parsed = urlparse(api_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            errors.append(f"Peer '{name}': Control API URL must be http://<IP>:<port>/ or https://<IP>:<port>/.")
            continue
        try:
            ipaddress.ip_address(parsed.hostname)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            errors.append(f"Peer '{name}': Control API URL must use an IP address and a valid port.")
            continue
        ha = urlparse(ha_urls[name])
        if ha.hostname == parsed.hostname and (ha.port or 80) == port:
            errors.append(
                f"Peer '{name}': the Control API URL and the HA listener URL both use port {port}. "
                f"Use a separate port for the API (8000 is conventional)."
            )
            continue
        result[name] = {"api-url": api_url if api_url.endswith("/") else api_url + "/"}
    return result, errors


# --- talking to a peer ----------------------------------------------------------

def peer_command(api_url: str, auth: Dict[str, str], command: str,
                 arguments: Optional[Dict[str, Any]] = None, timeout: float = 10.0) -> Dict[str, Any]:
    """Send one allowlisted command to a peer's Kea HTTP control socket."""
    if command not in ALLOWED_PEER_COMMANDS:
        raise PeerApiError(f"'{command}' is not an allowed peer command")
    body: Dict[str, Any] = {"command": command}
    if arguments is not None:
        body["arguments"] = arguments
    token = base64.b64encode(f"{auth['username']}:{auth['password']}".encode()).decode()
    req = urllib.request.Request(
        api_url, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Basic {token}"},
    )
    context = None
    if api_url.startswith("https"):
        context = ssl.create_default_context(cafile=auth.get("ca-file") or None)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise PeerApiError("the peer rejected EZ-KEA's credentials (HTTP %d)" % e.code)
        raise PeerApiError(f"HTTP {e.code} from the peer's control API")
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, ssl.SSLError) or isinstance(e, ssl.SSLError):
            # A setup problem, not an outage: don't offer "apply here only".
            raise PeerApiError(
                f"TLS check of {api_url} failed ({reason}). Set the CA File under Peer Config Sync "
                f"to the CA that signed the peer's certificate."
            )
        raise PeerApiError(f"could not reach {api_url}: {reason}", unreachable=True)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        raise PeerApiError("the peer's control API returned something that is not JSON")
    # Kea answers a list (one entry per service) when "service" is not given.
    if isinstance(parsed, list):
        parsed = parsed[0] if parsed else {}
    if not isinstance(parsed, dict):
        raise PeerApiError("unexpected response shape from the peer's control API")
    return parsed


def build_push_config(local_config: Dict[str, Any], dhcp_key: str, peer: str,
                      peer_live: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The config to send to `peer`: ours with this-server-name changed, plus
    the keys the peer owns, taken from its running config."""
    desired = peer_config(local_config, dhcp_key, peer)
    if desired is None:
        return None
    live = (peer_live or {}).get(dhcp_key, {})
    block = desired[dhcp_key]
    for key in PEER_OWNED_KEYS:
        block.pop(key, None)
        if key in live:
            block[key] = copy.deepcopy(live[key])
    # Only the daemon's own block is pushed; a top-level "hash" from
    # config-get or anything else is not part of a config-set.
    return {dhcp_key: block}


def local_sha(config: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def managed_peers(config: Dict[str, Any], dhcp_key: str) -> List[Tuple[str, str]]:
    """(name, api-url) for each HA peer, other than this server, with an API URL set."""
    ha = get_ha_params(config, dhcp_key)
    if not ha:
        return []
    apis = get_peer_apis(dhcp_key)
    out = []
    for p in ha.get("peers", []):
        name = p.get("name")
        if name and name != ha.get("this-server-name") and apis.get(name, {}).get("api-url"):
            out.append((name, apis[name]["api-url"]))
    return out


def unmanaged_peers(config: Dict[str, Any], dhcp_key: str) -> List[str]:
    ha = get_ha_params(config, dhcp_key) or {}
    managed = {n for n, _ in managed_peers(config, dhcp_key)}
    return [p["name"] for p in ha.get("peers", [])
            if p.get("name") != ha.get("this-server-name") and p.get("name") not in managed]


def preflight(config: Dict[str, Any], dhcp_key: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    For every managed peer: fetch its live config, build what it should run,
    and have the peer config-test it. Returns (ready, failed). Each ready item
    holds the config to push; each failed item has `error` and `unreachable`.
    Nothing on any peer changes here.
    """
    ready, failed = [], []
    peers = managed_peers(config, dhcp_key)
    if not peers:
        return ready, failed
    auth = get_auth()
    for name, url in peers:
        try:
            got = peer_command(url, auth, "config-get")
            if got.get("result") != 0:
                raise PeerApiError(f"config-get failed: {got.get('text', 'unknown error')}")
            push = build_push_config(config, dhcp_key, name, got.get("arguments", {}))
            if push is None:
                raise PeerApiError("not in this server's HA peer list")
            tested = peer_command(url, auth, "config-test", push)
            if tested.get("result") != 0:
                raise PeerApiError(f"rejected the config: {tested.get('text', 'unknown error')}")
            live = got.get("arguments", {})
            ready.append({"name": name, "url": url, "config": push,
                          "previous": {dhcp_key: live[dhcp_key]} if dhcp_key in live else None})
        except PeerApiError as e:
            failed.append({"name": name, "url": url, "error": str(e), "unreachable": e.unreachable})
    return ready, failed


def rollback(staged: List[Dict[str, Any]]) -> List[str]:
    """Put each staged peer back on the config it ran before (from preflight's
    config-get). Returns a note per peer."""
    notes = []
    if not staged:
        return notes
    auth = get_auth()
    for item in staged:
        if not item.get("previous"):
            notes.append(f"{item['name']}: no previous config to restore; check it by hand")
            continue
        try:
            res = peer_command(item["url"], auth, "config-set", item["previous"])
            ok = res.get("result") == 0
            notes.append(f"{item['name']} restored to its previous config" if ok
                         else f"{item['name']}: restoring its previous config failed: {res.get('text', '')}; check it by hand")
        except PeerApiError as e:
            notes.append(f"{item['name']}: restoring its previous config failed: {e}; check it by hand")
    return notes


def stage(ready: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], str]:
    """
    config-set on each preflighted peer, before this server reloads.
    config-test does not load hook libraries, so a peer missing one passes
    preflight and fails here, and Kea then drops its hooks (HA included)
    until a good config loads. So on any failure every peer touched so far,
    the failing one included, is put back on its previous config, and the
    caller applies nothing. Returns (staged, error); error is "" on success.
    """
    staged: List[Dict[str, Any]] = []
    if not ready:
        return staged, ""
    auth = get_auth()
    for item in ready:
        try:
            res = peer_command(item["url"], auth, "config-set", item["config"])
        except PeerApiError as e:
            notes = rollback(staged + [item])
            return [], f"{item['name']}: {e}. " + "; ".join(notes) + "."
        if res.get("result") != 0:
            notes = rollback(staged + [item])
            return [], f"{item['name']} could not load the config: {res.get('text', 'unknown error')}. " + "; ".join(notes) + "."
        item["hash"] = (res.get("arguments") or {}).get("hash", "")
        staged.append(item)
    return staged, ""


def commit(staged: List[Dict[str, Any]], dhcp_key: str, config: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """After this server reloaded: config-write on each staged peer so its own
    file matches, and record the push. Returns (done, errors)."""
    done, errors = [], []
    if not staged:
        return done, errors
    auth = get_auth()
    sha = local_sha(config)
    for item in staged:
        name, url = item["name"], item["url"]
        try:
            written = peer_command(url, auth, "config-write")
            if written.get("result") != 0:
                raise PeerApiError(
                    f"running the new config but could not save it to its config file: {written.get('text', '')}"
                )
            peer_hash = item.get("hash") or (peer_command(url, auth, "config-hash-get").get("arguments") or {}).get("hash", "")
            _record_push(dhcp_key, name, peer_hash, sha)
            done.append(name)
        except PeerApiError as e:
            errors.append(f"{name}: {e}")
    return done, errors


def sync_status(config: Dict[str, Any], dhcp_key: str) -> List[Dict[str, Any]]:
    """
    Per managed peer: in sync only if the peer's config hash is the one it
    reported at our last push and this server's config hasn't changed since.
    """
    out: List[Dict[str, Any]] = []
    peers = managed_peers(config, dhcp_key)
    auth = get_auth() if peers else {}
    state = _get_state(dhcp_key)
    sha = local_sha(config)
    for name, url in peers:
        entry: Dict[str, Any] = {"name": name, "url": url, "pushed-at": state.get(name, {}).get("pushed-at", "")}
        rec = state.get(name)
        try:
            res = peer_command(url, auth, "config-hash-get", timeout=5.0)
            peer_hash = (res.get("arguments") or {}).get("hash", "")
        except PeerApiError as e:
            entry.update(status="unreachable" if e.unreachable else "error", detail=str(e))
            out.append(entry)
            continue
        if not rec:
            entry.update(status="out-of-sync", detail="never pushed from EZ-KEA")
        elif rec.get("peer-hash") != peer_hash:
            entry.update(status="out-of-sync", detail="its config was changed outside EZ-KEA since the last push")
        elif rec.get("local-sha") != sha:
            entry.update(status="out-of-sync", detail="this server's config changed since the last push (Apply to push it)")
        else:
            entry.update(status="in-sync", detail="")
        out.append(entry)
    for name in unmanaged_peers(config, dhcp_key):
        out.append({"name": name, "url": "", "status": "unmanaged",
                    "detail": "no Control API URL set; load its config by hand"})
    return out


# --- one-time bootstrap ---------------------------------------------------------

def bootstrap_config(local_config: Dict[str, Any], dhcp_key: str, peer: str, api_url: str) -> Optional[Dict[str, Any]]:
    """Peer config plus an HTTP(S) control socket on the API URL's address and
    port, authenticated with the credential files the bootstrap script writes."""
    desired = peer_config(local_config, dhcp_key, peer)
    if desired is None:
        return None
    parsed = urlparse(api_url)
    block = desired[dhcp_key]
    sockets = block.pop("control-sockets", block.pop("control-socket", []))
    if isinstance(sockets, dict):
        sockets = [sockets]
    sockets = [s for s in sockets if isinstance(s, dict) and s.get("socket-type", "unix") == "unix"]
    entry: Dict[str, Any] = {
        "socket-type": parsed.scheme,
        "socket-address": parsed.hostname,
        "socket-port": parsed.port or (443 if parsed.scheme == "https" else DEFAULT_API_PORT),
        "authentication": {
            "type": "basic",
            "realm": API_REALM,
            "directory": CREDENTIAL_DIR,
            "clients": [{"user-file": USER_FILE, "password-file": PASSWORD_FILE}],
        },
    }
    if parsed.scheme == "https":
        entry.update({"trust-anchor": f"{CREDENTIAL_DIR}/ez-kea-ca.pem", "cert-file": f"{CREDENTIAL_DIR}/ez-kea-api.pem",
                      "key-file": f"{CREDENTIAL_DIR}/ez-kea-api.key", "cert-required": False})
    sockets.append(entry)
    block["control-sockets"] = sockets
    return desired


def bootstrap_script(local_config: Dict[str, Any], dhcp_key: str, peer: str, api_url: str) -> Optional[str]:
    """A POSIX shell script, run once as root on the peer, that installs its
    config and API credentials and reloads Kea. Contains the API password."""
    cfg = bootstrap_config(local_config, dhcp_key, peer, api_url)
    if cfg is None:
        return None
    v = "6" if dhcp_key == "Dhcp6" else "4"
    auth = get_auth()
    body = json.dumps(cfg, indent=2)
    if "EZKEA_CONFIG_EOF" in body:  # cannot happen with JSON from json.dumps, but never break the heredoc
        return None
    https_note = ""
    if api_url.startswith("https"):
        https_note = (
            f"# HTTPS: put the peer's certificate and key in {CREDENTIAL_DIR}/ez-kea-api.pem and\n"
            f"# {CREDENTIAL_DIR}/ez-kea-api.key, and the CA in {CREDENTIAL_DIR}/ez-kea-ca.pem, before running.\n"
        )
    return f"""#!/bin/sh
# EZ-KEA one-time setup for HA peer '{peer}' (kea-dhcp{v}).
# Run once on {peer} as root:  sh {shlex.quote(f'ez-kea-bootstrap-{peer}-v{v}.sh')} [config-file]
# It installs this server's config (with this-server-name = {peer}) and a Kea
# control API on {api_url} so EZ-KEA can push every later change itself.
# Contains the API password: delete this file after running it.
{https_note}set -eu
CONF="${{1:-/etc/kea/kea-dhcp{v}.conf}}"
DIR={shlex.quote(CREDENTIAL_DIR)}
[ "$(id -u)" = 0 ] || {{ echo "Run as root." >&2; exit 1; }}
command -v kea-dhcp{v} >/dev/null || {{ echo "kea-dhcp{v} not found; install Kea 3.x first." >&2; exit 1; }}
GROUP=$(stat -c %G "$CONF" 2>/dev/null || stat -c %G "$DIR")
umask 027
TMP=$(mktemp "$DIR/.ez-kea-bootstrap.XXXXXX")
trap 'rm -f "$TMP"' EXIT
cat > "$TMP" <<'EZKEA_CONFIG_EOF'
{body}
EZKEA_CONFIG_EOF
printf '%s' {shlex.quote(auth['username'])} > "$DIR/{USER_FILE}"
printf '%s' {shlex.quote(auth['password'])} > "$DIR/{PASSWORD_FILE}"
chgrp "$GROUP" "$DIR/{USER_FILE}" "$DIR/{PASSWORD_FILE}" "$TMP"
chmod 640 "$DIR/{USER_FILE}" "$DIR/{PASSWORD_FILE}" "$TMP"
if ! kea-dhcp{v} -t "$TMP" >/tmp/ez-kea-bootstrap.log 2>&1; then
    tail -5 /tmp/ez-kea-bootstrap.log >&2
    echo "Config test failed; $CONF was not changed." >&2
    exit 1
fi
if [ -f "$CONF" ]; then
    cp -p "$CONF" "$CONF.pre-ez-kea.$(date +%Y%m%d%H%M%S)"
    cat "$TMP" > "$CONF"   # keep the existing file's owner and mode
else
    cp "$TMP" "$CONF"
fi
for unit in isc-kea-dhcp{v}-server kea-dhcp{v}-server kea-dhcp{v}; do
    if command -v systemctl >/dev/null && systemctl cat "$unit.service" >/dev/null 2>&1; then
        systemctl restart "$unit"
        echo "Restarted $unit. EZ-KEA can now manage {peer} at {api_url}"
        exit 0
    fi
done
if pkill -HUP -x kea-dhcp{v}; then
    echo "Sent SIGHUP to kea-dhcp{v}. EZ-KEA can now manage {peer} at {api_url}"
else
    echo "Config installed. Start kea-dhcp{v} with $CONF."
fi
"""
