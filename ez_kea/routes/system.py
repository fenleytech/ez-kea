import shlex
import subprocess
import os
import json
from typing import Dict, Tuple, Union, Any
from flask_login import login_required
from flask import Blueprint, render_template, request, redirect, url_for, jsonify, current_app, flash
from werkzeug.wrappers import Response
from ..core.config_manager import (
    load_json, save_json, copy_file, extract_log_file_from_config,
    with_config_lock, config_lock, bootstrap_config, bootstrap_config6, _DEFAULT_KEA6_CONFIG,
)
from ..core.settings_manager import load_settings, save_settings
from ..core.security import validate_kea_command, validate_log_file_path, InvalidKeaCommandError, InvalidLogPathError

system_bp = Blueprint('system', __name__)

# Global timers are Kea uint32 fields — reject non-positive and absurdly
# large values instead of letting an invalid value reach the Kea config.
TIMER_FIELDS = ("valid-lifetime", "max-valid-lifetime", "renew-timer", "rebind-timer")
# DHCPv6 has every v4 timer plus preferred-lifetime (no v4 equivalent).
TIMER_FIELDS6 = TIMER_FIELDS + ("preferred-lifetime",)
MIN_TIMER_VALUE = 1
MAX_TIMER_VALUE = 4294967295  # 2**32 - 1

# DHCPv6 global option-data presets, parallel to v4's GLOBAL_OPTIONS below —
# different option namespace (dns-servers/sntp-servers/domain-search rather
# than domain-name-servers/ntp-servers/domain-name).
def _global_settings_field_names(version: str) -> Dict[str, str]:
    """Form-field names and settings-key prefix for the given DHCP version's
    global-settings form. v4 names are unchanged from before version-aware
    routes existed, so the original template/form keeps working verbatim."""
    if version == "6":
        return {
            "cmd_field": "kea-dhcp6-cmd",
            "log_file_field": "dhcp6-log-file",
            "config_file_field": "dhcp6-config-file",
            "leases_file_field": "dhcp6-leases-file",
            "config_file_in_container_field": "dhcp6-config-file-in-container",
            "log_file_in_container_field": "dhcp6-log-file-in-container",
            "settings_prefix": "dhcp6",
            "cmd_settings_key": "kea_dhcp6_cmd",
        }
    return {
        "cmd_field": "kea-dhcp4-cmd",
        "log_file_field": "dhcp-log-file",
        "config_file_field": "dhcp-config-file",
        "leases_file_field": "dhcp-leases-file",
        "config_file_in_container_field": "dhcp-config-file-in-container",
        "log_file_in_container_field": "dhcp-log-file-in-container",
        "settings_prefix": "dhcp",
        "cmd_settings_key": "kea_dhcp4_cmd",
    }

# --- Docker-deployment helpers ----------------------------------------------
# These centralize the "host path vs. in-container path" and "which container"
# concerns so /test-config, /apply-config, and /save-global-settings agree on
# them. See AUDIT_FINDINGS.md section 2.3 for the failure modes this fixes.

def _resolve_daemon_config(version: str) -> Dict[str, str]:
    """
    Centralizes the version(4/6)->config-key mapping so /test-config,
    /apply-config, /backup-config, and /restore-config all agree on which
    file/command/logger they're acting on, instead of each hardcoding v4.
    """
    # leases_file/log_file are only actually read by the logs/global-settings
    # code paths, not by test/apply/backup/restore — looked up via .get() so
    # callers that only need config_file/cmd_key aren't forced to also
    # configure DHCP(6)_LEASES_FILE/DHCP(6)_LOG_FILE.
    if version == "6":
        return {
            "config_file": current_app.config["DHCP6_CONFIG_FILE"],
            "config_file_in_container": current_app.config.get("DHCP6_CONFIG_FILE_IN_CONTAINER", ""),
            "cmd_key": "KEA_DHCP6_CMD",
            "leases_file": current_app.config.get("DHCP6_LEASES_FILE", ""),
            "log_file": current_app.config.get("DHCP6_LOG_FILE", ""),
            "log_file_in_container": current_app.config.get("DHCP6_LOG_FILE_IN_CONTAINER", ""),
            "dhcp_root_key": "Dhcp6",
            "logger_name": "kea-dhcp6",
        }
    return {
        "config_file": current_app.config["DHCP_CONFIG_FILE"],
        "config_file_in_container": current_app.config.get("DHCP_CONFIG_FILE_IN_CONTAINER", ""),
        "cmd_key": "KEA_DHCP4_CMD",
        "leases_file": current_app.config.get("DHCP_LEASES_FILE", ""),
        "log_file": current_app.config.get("DHCP_LOG_FILE", ""),
        "log_file_in_container": current_app.config.get("DHCP_LOG_FILE_IN_CONTAINER", ""),
        "dhcp_root_key": "Dhcp4",
        "logger_name": "kea-dhcp4",
    }


def _in_container_config_path(daemon: Dict[str, str]) -> str:
    """
    Path to pass to `-t` when invoking a Kea DHCP daemon command.

    Distinct from the host-side config path EZ-Kea itself reads/writes
    because when the command execs into a Docker container (`docker exec
    <container> kea-dhcp4|kea-dhcp6`), the binary runs inside the container's
    own filesystem namespace, where the host path may not exist. Falls back
    to the host path, which is correct for bare-metal/non-Docker deployments.
    """
    in_container = daemon["config_file_in_container"].strip()
    return in_container or daemon["config_file"]


def _parse_docker_container(cmd: str) -> str:
    """
    Best-effort extraction of the container name from a `docker exec
    <container> ...`-style command string.

    Read-only-validation use only (e.g. checking a directory exists before
    writing a path into Kea's config) — NEVER used to decide which command to
    actually execute for a reload. That decision is always the explicit
    KEA_RELOAD_STRATEGY / KEA_DOCKER_CONTAINER setting; guessing wrong there
    is worse than requiring the extra field.
    """
    try:
        tokens = shlex.split(cmd or "")
    except ValueError:
        return ""
    if len(tokens) >= 3 and tokens[0] == "docker" and tokens[1] == "exec":
        for tok in tokens[2:]:
            if not tok.startswith("-"):
                return tok
    return ""


def _docker_container_hint() -> str:
    """Best-effort container name for read-only validation (see _parse_docker_container)."""
    explicit = current_app.config.get("KEA_DOCKER_CONTAINER", "").strip()
    if explicit:
        return explicit
    for cmd_key in ("KEA_DHCP4_CMD", "KEA_CTRL_CMD"):
        container = _parse_docker_container(current_app.config.get(cmd_key, ""))
        if container:
            return container
    return ""


def _dir_exists(path: str) -> bool:
    """
    Check whether the parent directory of `path` exists, from the correct
    filesystem perspective: inside the Kea container if one is configured or
    discoverable (Docker deployments), else on the host running EZ-Kea.
    """
    directory = os.path.dirname(path) or "."
    container = _docker_container_hint()
    if container:
        try:
            probe = subprocess.run(
                ["docker", "exec", container, "test", "-d", directory],
                capture_output=True, timeout=5,
            )
            return probe.returncode == 0
        except Exception:
            return False
    return os.path.isdir(directory)


def _log_file_for_viewing(version: str = "4") -> str:
    """
    Path EZ-Kea's own (host-side) /logs viewer should open, for the given
    DHCP version (4 or 6; defaults to 4 for the existing /logs route).

    When a distinct in-container log path is configured (Docker deployments —
    see DHCP_LOG_FILE_IN_CONTAINER), the value written into Kea's own config
    is a container-namespace path the host Flask process cannot open, so we
    trust our own DHCP_LOG_FILE setting instead of re-reading it back out of
    the Kea config. Bare-metal/non-Docker installs (no in-container path
    configured) keep the old behavior of trusting whatever's actually in the
    Kea config, in case it was hand-edited outside EZ-Kea.
    """
    daemon = _resolve_daemon_config(version)
    if daemon["log_file_in_container"].strip():
        return daemon["log_file"]
    return extract_log_file_from_config(
        daemon["config_file"], daemon["log_file"],
        dhcp_key=daemon["dhcp_root_key"], logger_name=daemon["logger_name"],
    )

@system_bp.route("/")
@login_required
def index() -> str:
    """Render the dashboard/index page."""
    return render_template("index.html")

def _invalid_version_response() -> Tuple[Response, int]:
    return jsonify({"error": "Unknown DHCP version — must be '4' or '6'"}), 400


@system_bp.route("/backup-config", methods=["POST"])
@system_bp.route("/backup-config/<version>", methods=["POST"])
@login_required
def backup_config(version: str = "4") -> Union[Response, Tuple[Response, int]]:
    """Backup the current Kea configuration (v4 or v6) to the backup directory."""
    if version not in ("4", "6"):
        return _invalid_version_response()
    daemon = _resolve_daemon_config(version)
    # Lock on the resolved config file, not a fixed key — with_config_lock()
    # can't do this itself since the file to lock depends on the `version`
    # route argument, which isn't known until the view is actually called.
    with config_lock(daemon["config_file"]):
        try:
            copy_file(daemon["config_file"], current_app.config["BACKUP_DIR"])
            return redirect(request.referrer or url_for("main.system.index"))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@system_bp.route("/restore-config", methods=["POST"])
@system_bp.route("/restore-config/<version>", methods=["POST"])
@login_required
def restore_config(version: str = "4") -> Union[Response, Tuple[Response, int]]:
    """Restore Kea configuration (v4 or v6) from the most recent backup."""
    if version not in ("4", "6"):
        return _invalid_version_response()
    daemon = _resolve_daemon_config(version)
    with config_lock(daemon["config_file"]):
        try:
             copy_file(daemon["config_file"], current_app.config["BACKUP_DIR"], restore=True)
             return redirect(request.referrer or url_for("main.system.index"))
        except Exception as e:
             return jsonify({"error": str(e)}), 500

def _test_config_impl(version: str) -> Union[Response, Tuple[Response, int]]:
    """Test the syntactic validity of the Kea configuration file for `version`."""
    daemon = _resolve_daemon_config(version)
    try:
        command = validate_kea_command(current_app.config[daemon["cmd_key"]], f"kea-dhcp{version}-cmd")
    except InvalidKeaCommandError as e:
        return jsonify({"error": str(e)}), 400
    command = command + ["-t", _in_container_config_path(daemon)]
    try:
        subprocess.run(command, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        error_msg = f"{e.stdout}\n{e.stderr}".strip()
        if "Syntax check failed" in error_msg or "error" in error_msg.lower():
            return jsonify({"error": f"Syntax error in configuration file: {error_msg}"}), 500
        else:
            return jsonify({"error": error_msg}), 500
    except FileNotFoundError as e:
        return jsonify({"error": f"Could not run Kea syntax check — binary not found: {e}"}), 500
    return jsonify({"message": "Syntax check passed!"})

@system_bp.route("/test-config", methods=["POST"])
@login_required
def test_config() -> Union[Response, Tuple[Response, int]]:
    """Test the syntactic validity of the DHCPv4 Kea configuration file."""
    return _test_config_impl("4")

@system_bp.route("/test-config/<version>", methods=["POST"])
@login_required
def test_config_version(version: str) -> Union[Response, Tuple[Response, int]]:
    """Test the syntactic validity of the Kea configuration file for the given version (4 or 6)."""
    if version not in ("4", "6"):
        return _invalid_version_response()
    return _test_config_impl(version)

def _apply_config_impl(version: str) -> Union[Response, Tuple[Response, int]]:
    """Validate syntax and reload the Kea service for `version` with the current config."""
    # Attempt syntax test first
    test_result = _test_config_impl(version)
    status_code = test_result[1] if isinstance(test_result, tuple) else getattr(test_result, 'status_code', 200)
    if status_code != 200:
        return test_result

    strategy = current_app.config.get("KEA_RELOAD_STRATEGY", "keactrl")
    if strategy == "sighup":
        container = current_app.config.get("KEA_DOCKER_CONTAINER", "").strip()
        if not container:
            return jsonify({
                "error": "Reload strategy is set to 'Docker container SIGHUP' but no Docker "
                         "container name is configured. Set it in Global Settings before "
                         "applying — this is required explicitly and never guessed."
            }), 500
        command = ["docker", "kill", "-s", "HUP", container]
    else:
        try:
            command = validate_kea_command(current_app.config["KEA_CTRL_CMD"], "kea-ctrl-cmd")
        except InvalidKeaCommandError as e:
            return jsonify({"error": str(e)}), 400
        command = command + ["reload"]

    try:
        subprocess.run(command, capture_output=True, text=True, check=True)
        return jsonify({"message": "KEA service reloaded successfully!"})
    except subprocess.CalledProcessError as e:
        error_msg = f"{e.stdout}\n{e.stderr}".strip()
        return jsonify({"error": f"KEA service reload failed: {error_msg}"}), 500
    except FileNotFoundError as e:
        return jsonify({"error": f"Could not reload Kea — control binary not found: {e}"}), 500

@system_bp.route("/apply-config", methods=["POST"])
@login_required
def apply_config() -> Union[Response, Tuple[Response, int]]:
    """Validate functionality and reload the DHCPv4 Kea service with the current config."""
    return _apply_config_impl("4")

@system_bp.route("/apply-config/<version>", methods=["POST"])
@login_required
def apply_config_version(version: str) -> Union[Response, Tuple[Response, int]]:
    """Validate functionality and reload the Kea service for the given version (4 or 6)."""
    if version not in ("4", "6"):
        return _invalid_version_response()
    return _apply_config_impl(version)

@system_bp.route("/logs", methods=["GET", "POST"])
@login_required
def logs() -> str:
    """
    Render Kea DHCP logs. Features a search query and limits extraction to the
    last 1000 lines for memory safety, handling Unicode decoding gracefully.
    """
    from collections import deque
    search_query = request.form.get("search_query", "")
    log_lines = []
    
    log_file = _log_file_for_viewing()
    
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8", errors="replace") as file:
            log_lines = list(deque(file, maxlen=1000))
        log_lines.reverse()
        
    if search_query:
        search_lower = search_query.lower()
        log_lines = [line for line in log_lines if search_lower in line.lower()]

    return render_template("logs.html", log_lines=log_lines, search_query=search_query)

def _build_global_settings_context(version: str = "4") -> Dict[str, Any]:
    """Build the template context shared by the global-settings GET view and
    the error-path re-render of the same page after a failed POST."""
    daemon = _resolve_daemon_config(version)
    names = _global_settings_field_names(version)
    prefix = names["settings_prefix"]

    config = load_json(daemon["config_file"], default=_DEFAULT_KEA6_CONFIG if version == "6" else None)
    dhcp = config.get(daemon["dhcp_root_key"], {})

    filtered_settings = {k: v for k, v in dhcp.items() if k != "shared-networks"}
    global_options = {opt["name"]: opt["data"] for opt in dhcp.get("option-data", [])}
    ez_kea_settings = load_settings(current_app.config["SETTINGS_FILE"])
    # Overlay current app config values (env vars take priority over saved settings)
    ez_kea_settings[f"{prefix}_config_file"] = daemon["config_file"]
    ez_kea_settings[f"{prefix}_leases_file"] = daemon["leases_file"]
    ez_kea_settings[f"{prefix}_log_file"]    = _log_file_for_viewing(version)
    ez_kea_settings[names["cmd_settings_key"]] = current_app.config[daemon["cmd_key"]]
    ez_kea_settings["kea_ctrl_cmd"]     = current_app.config["KEA_CTRL_CMD"]
    ez_kea_settings[f"{prefix}_config_file_in_container"] = daemon["config_file_in_container"]
    ez_kea_settings[f"{prefix}_log_file_in_container"]    = daemon["log_file_in_container"]
    ez_kea_settings["kea_reload_strategy"]  = current_app.config.get("KEA_RELOAD_STRATEGY", "keactrl")
    ez_kea_settings["kea_docker_container"] = current_app.config.get("KEA_DOCKER_CONTAINER", "")

    return {
        "version": version,
        "global_settings": filtered_settings,
        "global_options": global_options,
        "ez_kea_settings": ez_kea_settings,
    }

@system_bp.route("/global-settings")
@login_required
def global_settings() -> str:
    """Render the global DHCPv4 Kea configuration settings page."""
    return render_template("global_settings.html", **_build_global_settings_context("4"))

@system_bp.route("/global-settings/<version>")
@login_required
def global_settings_version(version: str) -> Union[str, Tuple[str, int]]:
    """Render the global Kea configuration settings page for the given version (4 or 6)."""
    if version not in ("4", "6"):
        return "Unknown DHCP version — must be '4' or '6'", 400
    return render_template("global_settings.html", **_build_global_settings_context(version))

def _save_global_settings_impl(version: str) -> Union[Response, Tuple[str, int]]:
    """Save user-updated global configuration parameters for the given DHCP
    version (4 or 6)."""
    daemon = _resolve_daemon_config(version)
    names = _global_settings_field_names(version)
    prefix = names["settings_prefix"]
    redirect_endpoint = "main.system.global_settings" if version == "4" else "main.system.global_settings_version"
    redirect_kwargs = {} if version == "4" else {"version": version}
    current_config_file = daemon["config_file"]

    # ── Validate security-sensitive fields up front. Any failure here aborts
    # the whole save with no changes written anywhere (see AUDIT_FINDINGS.md
    # 1.1 and 1.2) ────────────────────────────────────────────────────────
    errors = []

    # Only (re-)validate a command field when it's actually being changed. If we
    # revalidated the already-stored value on every save regardless, an
    # unrelated settings change (e.g. just updating the DNS option) would fail
    # outright the moment the previously-configured kea-dhcp4/keactrl binary
    # stops resolving (host rebuilt, PATH changed, etc.) — that's a usability
    # regression, not a security requirement. The actual security boundary
    # (can't exec anything but an allowed, executable binary) is still fully
    # enforced at set-time here AND, independently, at execution time in
    # test_config()/apply_config() regardless of how the value got there.
    candidate_dhcp_cmd = request.form.get(names["cmd_field"], "").strip() or current_app.config[daemon["cmd_key"]]
    candidate_ctrl_cmd  = request.form.get("kea-ctrl-cmd", "").strip()  or current_app.config["KEA_CTRL_CMD"]
    if candidate_dhcp_cmd != current_app.config[daemon["cmd_key"]]:
        try:
            validate_kea_command(candidate_dhcp_cmd, names["cmd_field"])
        except InvalidKeaCommandError as e:
            errors.append(str(e))
    if candidate_ctrl_cmd != current_app.config["KEA_CTRL_CMD"]:
        try:
            validate_kea_command(candidate_ctrl_cmd, "kea-ctrl-cmd")
        except InvalidKeaCommandError as e:
            errors.append(str(e))

    candidate_log_file = request.form.get(names["log_file_field"], "").strip() or daemon["log_file"]
    if candidate_log_file != daemon["log_file"]:
        try:
            validate_log_file_path(
                candidate_log_file, current_config_file, daemon["log_file"],
                dhcp_key=daemon["dhcp_root_key"], logger_name=daemon["logger_name"],
            )
        except InvalidLogPathError as e:
            errors.append(str(e))

    if errors:
        for e in errors:
            flash(e, "danger")
        return redirect(url_for(redirect_endpoint, **redirect_kwargs))

    # ── Config-file repoint is a distinct action, not a save (AUDIT_FINDINGS.md
    # 1.3): if the operator is pointing EZ-Kea at a different config file, we
    # must NOT also write whatever's currently loaded into memory (from the
    # OLD path) over the top of the NEW path. Just switch the pointer, and
    # require the target to either not exist yet (first-time setup) or
    # already contain parseable Kea JSON. ─────────────────────────────────
    candidate_config_file = request.form.get(names["config_file_field"], "").strip() or current_config_file
    if candidate_config_file != current_config_file:
        resolved_target = os.path.abspath(candidate_config_file)
        if os.path.exists(resolved_target):
            try:
                with open(resolved_target, "r") as f:
                    parsed = json.load(f)
                if not isinstance(parsed, dict) or daemon["dhcp_root_key"] not in parsed:
                    raise ValueError(f"missing '{daemon['dhcp_root_key']}' root key")
            except (json.JSONDecodeError, ValueError, OSError) as e:
                flash(
                    f"{names['config_file_field']}: '{candidate_config_file}' already exists but is not a "
                    f"valid Kea DHCPv{version} config ({e}); refusing to repoint to avoid clobbering it.",
                    "danger",
                )
                return redirect(url_for(redirect_endpoint, **redirect_kwargs))

        # Start from the full merged settings (not just this version's
        # fields) so saving one version's settings never silently wipes the
        # other version's persisted settings out of the shared settings file.
        new_settings = dict(load_settings(current_app.config["SETTINGS_FILE"]))
        new_settings[names["cmd_settings_key"]] = candidate_dhcp_cmd
        new_settings["kea_ctrl_cmd"] = candidate_ctrl_cmd
        new_settings[f"{prefix}_config_file"] = resolved_target
        new_settings[f"{prefix}_leases_file"] = request.form.get(names["leases_file_field"], "").strip() or daemon["leases_file"]
        new_settings[f"{prefix}_log_file"] = candidate_log_file
        save_settings(current_app.config["SETTINGS_FILE"], new_settings)
        current_app.config[daemon["cmd_key"]] = new_settings[names["cmd_settings_key"]]
        current_app.config["KEA_CTRL_CMD"] = new_settings["kea_ctrl_cmd"]
        current_app.config["DHCP6_CONFIG_FILE" if version == "6" else "DHCP_CONFIG_FILE"] = new_settings[f"{prefix}_config_file"]
        current_app.config["DHCP6_LEASES_FILE" if version == "6" else "DHCP_LEASES_FILE"] = new_settings[f"{prefix}_leases_file"]
        current_app.config["DHCP6_LOG_FILE" if version == "6" else "DHCP_LOG_FILE"] = new_settings[f"{prefix}_log_file"]

        # First-time setup: create a minimal valid skeleton if nothing exists yet.
        if version == "6":
            bootstrap_config6(resolved_target, current_app.config["BACKUP_DIR"])
        else:
            bootstrap_config(resolved_target, current_app.config["BACKUP_DIR"])

        flash(
            f"Kea config file repointed to '{resolved_target}'. Other settings on this page "
            "were not applied — review and save again against the new file if needed.",
            "info",
        )
        return redirect(url_for(redirect_endpoint, **redirect_kwargs))

    # ── Validate timer fields up front so a bad value never partially
    # mutates the config before we know the whole submission is clean.
    timer_fields = TIMER_FIELDS6 if version == "6" else TIMER_FIELDS
    parsed_timers: Dict[str, int] = {}
    timer_errors = []
    for timer in timer_fields:
        raw_value = request.form.get(timer, "").strip()
        if not raw_value:
            continue
        try:
            value = int(raw_value)
        except ValueError:
            timer_errors.append(f"{timer.replace('-', ' ').title()} must be a whole number.")
            continue
        if value < MIN_TIMER_VALUE or value > MAX_TIMER_VALUE:
            timer_errors.append(
                f"{timer.replace('-', ' ').title()} must be between {MIN_TIMER_VALUE} and {MAX_TIMER_VALUE}."
            )
            continue
        parsed_timers[timer] = value

    if timer_errors:
        return render_template("global_settings.html", errors=timer_errors, **_build_global_settings_context(version)), 400

    # ── Normal case: same config file, apply edits and save ──────────────
    config = load_json(current_config_file, default=_DEFAULT_KEA6_CONFIG if version == "6" else None)
    if daemon["dhcp_root_key"] not in config: config[daemon["dhcp_root_key"]] = {}
    dhcp = config[daemon["dhcp_root_key"]]

    if "interfaces-config" in request.form:
        seen = set()
        interfaces = []
        for i in request.form["interfaces-config"].split(","):
            name = i.strip()
            if name and name not in seen:
                seen.add(name)
                interfaces.append(name)
        dhcp.setdefault("interfaces-config", {})["interfaces"] = interfaces

    for timer in timer_fields:
        if timer in parsed_timers:
            dhcp[timer] = parsed_timers[timer]
        elif timer in dhcp and not request.form.get(timer):
            # Clear field if user left it blank (optional timers)
            if timer in ("renew-timer", "rebind-timer"):
                dhcp.pop(timer, None)

    if "host-reservation-identifiers" in request.form:
        dhcp["host-reservation-identifiers"] = [
            i.strip() for i in request.form["host-reservation-identifiers"].split(",") if i.strip()
        ]

    # DHCPv6-only: server-id (Dhcp6.server-id). Only touched when the field
    # is present and non-blank — leaving it blank means "let Kea auto-generate
    # one," not "clear whatever's already there."
    if version == "6":
        server_id_type = request.form.get("server-id-type", "").strip()
        if server_id_type:
            server_id = dhcp.setdefault("server-id", {})
            server_id["type"] = server_id_type
            identifier = request.form.get("server-id-identifier", "").strip()
            if identifier:
                server_id["identifier"] = identifier

    # Global option-data: v4 gets DNS/NTP/domain-name, v6 gets its own
    # namespace (dns-servers/sntp-servers/domain-search).
    if version == "6":
        managed_options = {
            "dns-servers": request.form.get("opt-dns6", "").strip(),
            "sntp-servers": request.form.get("opt-sntp6", "").strip(),
            "domain-search": request.form.get("opt-domain-search6", "").strip(),
        }
    else:
        managed_options = {
            "domain-name-servers": request.form.get("opt-dns", "").strip(),
            "ntp-servers": request.form.get("opt-ntp", "").strip(),
            "domain-name": request.form.get("opt-domain", "").strip(),
        }
    existing_opts = dhcp.get("option-data", [])
    # Remove managed options then re-add non-empty ones
    existing_opts = [o for o in existing_opts if o.get("name") not in managed_options]
    for name, data in managed_options.items():
        if data:
            existing_opts.append({"name": name, "data": data})
    dhcp["option-data"] = existing_opts

    # Runtime EZ-Kea settings (Kea command paths, file paths) — persisted to
    # ez-kea-settings.json. Start from the full merged settings so this
    # version's save never clobbers the other version's persisted fields.
    new_settings = dict(load_settings(current_app.config["SETTINGS_FILE"]))
    new_settings[names["cmd_settings_key"]] = candidate_dhcp_cmd
    new_settings["kea_ctrl_cmd"] = candidate_ctrl_cmd
    new_settings[f"{prefix}_config_file"] = current_config_file
    new_settings[f"{prefix}_leases_file"] = request.form.get(names["leases_file_field"], "").strip() or daemon["leases_file"]
    new_settings[f"{prefix}_log_file"] = candidate_log_file
    # Docker-deployment settings (see ez_kea/config.py). Blank is a valid,
    # meaningful value here ("same as the host path/no override") so we
    # only fall back to the prior value when the field is altogether
    # absent from this POST (i.e. the *other* settings form was submitted).
    new_settings[f"{prefix}_config_file_in_container"] = (
        request.form[names["config_file_in_container_field"]].strip()
        if names["config_file_in_container_field"] in request.form
        else daemon["config_file_in_container"]
    )
    new_settings[f"{prefix}_log_file_in_container"] = (
        request.form[names["log_file_in_container_field"]].strip()
        if names["log_file_in_container_field"] in request.form
        else daemon["log_file_in_container"]
    )
    new_settings["kea_reload_strategy"] = (
        request.form.get("kea-reload-strategy", "").strip()
        or current_app.config.get("KEA_RELOAD_STRATEGY", "keactrl")
    )
    new_settings["kea_docker_container"] = (
        request.form["kea-docker-container"].strip()
        if "kea-docker-container" in request.form
        else current_app.config.get("KEA_DOCKER_CONTAINER", "")
    )

    # Also update the log file in Kea's own config so it's the source of
    # truth for the running daemon. Use the in-container path when one is
    # configured (Docker deployments) since that's the namespace Kea itself
    # actually reads/writes in — writing the host path verbatim there would
    # silently kill Kea's own logging the moment it's applied (see
    # AUDIT_FINDINGS.md 2.3).
    log_file_path = new_settings[f"{prefix}_log_file_in_container"] or new_settings[f"{prefix}_log_file"]

    if _dir_exists(log_file_path):
        loggers = dhcp.setdefault("loggers", [])
        found_logger = False
        for logger in loggers:
            if logger.get("name") == daemon["logger_name"]:
                found_logger = True
                opts = logger.setdefault("output_options", [{"output": log_file_path}])
                if opts:
                    opts[0]["output"] = log_file_path
                else:
                    opts.append({"output": log_file_path})
                break
        if not found_logger:
            loggers.append({
                "name": daemon["logger_name"],
                "severity": "INFO",
                "debuglevel": 0,
                "output_options": [{"output": log_file_path}]
            })
    else:
        container = _docker_container_hint()
        perspective = f"inside container '{container}'" if container else "on the host"
        flash(
            f"Log directory for '{log_file_path}' does not exist ({perspective}) — "
            "Kea's logger configuration was NOT changed, to avoid silently breaking its "
            "logging. Create the directory first (in Docker mode, inside the container "
            "Kea actually runs in), then save again.",
            "warning",
        )

    save_settings(current_app.config["SETTINGS_FILE"], new_settings)
    # Apply immediately to running app
    current_app.config[daemon["cmd_key"]] = new_settings[names["cmd_settings_key"]]
    current_app.config["KEA_CTRL_CMD"] = new_settings["kea_ctrl_cmd"]
    current_app.config["DHCP6_LEASES_FILE" if version == "6" else "DHCP_LEASES_FILE"] = new_settings[f"{prefix}_leases_file"]
    current_app.config["DHCP6_LOG_FILE" if version == "6" else "DHCP_LOG_FILE"] = new_settings[f"{prefix}_log_file"]
    current_app.config["DHCP6_CONFIG_FILE_IN_CONTAINER" if version == "6" else "DHCP_CONFIG_FILE_IN_CONTAINER"] = new_settings[f"{prefix}_config_file_in_container"]
    current_app.config["DHCP6_LOG_FILE_IN_CONTAINER" if version == "6" else "DHCP_LOG_FILE_IN_CONTAINER"] = new_settings[f"{prefix}_log_file_in_container"]
    current_app.config["KEA_RELOAD_STRATEGY"] = new_settings["kea_reload_strategy"]
    current_app.config["KEA_DOCKER_CONTAINER"] = new_settings["kea_docker_container"]

    save_json(config, current_config_file)
    return redirect(url_for(redirect_endpoint, **redirect_kwargs))

@system_bp.route("/save-global-settings", methods=["POST"])
@login_required
@with_config_lock()
def save_global_settings() -> Union[Response, Tuple[str, int]]:
    """Save user-updated DHCPv4 global configuration parameters."""
    return _save_global_settings_impl("4")

@system_bp.route("/save-global-settings/<version>", methods=["POST"])
@login_required
def save_global_settings_version(version: str) -> Union[Response, Tuple[str, int]]:
    """Save user-updated global configuration parameters for the given version (4 or 6)."""
    if version not in ("4", "6"):
        return "Unknown DHCP version — must be '4' or '6'", 400
    daemon = _resolve_daemon_config(version)
    with config_lock(daemon["config_file"]):
        return _save_global_settings_impl(version)


@system_bp.route("/api/system/discover")
@login_required
def api_discover() -> Response:
    """Endpoint for UI auto-discovery of Kea settings and modes."""
    from ..core.discovery import discover_environment
    # Force discovery by faking a non-existent settings file, so it sniffs /proc
    # and /etc instead of returning the user's saved overrides.
    fake_config = dict(current_app.config)
    fake_config["SETTINGS_FILE"] = "/nonexistent_force_discovery"
    env_info = discover_environment(fake_config)
    return jsonify(env_info)