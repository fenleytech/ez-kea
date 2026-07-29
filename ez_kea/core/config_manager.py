import json
import os
import shutil
import datetime
import fcntl
import hashlib
import threading
from contextlib import contextmanager
from functools import wraps

# Minimal valid Kea DHCPv4 skeleton written on first run
_DEFAULT_KEA_CONFIG = {
    "Dhcp4": {
        "interfaces-config": {
            "interfaces": []
        },
        "control-socket": {
            "socket-type": "unix",
            "socket-name": "/var/run/kea/kea-dhcp4-ctrl.sock"
        },
        "lease-database": {
            "type": "memfile",
            "lfc-interval": 3600,
            "name": "/var/lib/kea/kea-leases4.csv"
        },
        "host-reservation-identifiers": ["hw-address"],
        "valid-lifetime": 4000,
        "option-data": [],
        "shared-networks": [],
        "subnet4": [],
        "loggers": [
            {
                "name": "kea-dhcp4",
                "output_options": [
                    {
                        "output": "/var/log/kea/kea-dhcp4.log",
                        "maxver": 8,
                        "maxsize": 204800,
                        "flush": True
                    }
                ],
                "severity": "INFO",
                "debuglevel": 0
            }
        ]
    }
}

# Minimal valid Kea DHCPv6 skeleton written on first run. Kept as its own
# constant (rather than deriving it from _DEFAULT_KEA_CONFIG) since v6's
# control-socket/lease-database/logger paths and the extra preferred-lifetime
# field are genuinely different, not just a Dhcp4->Dhcp6 rename.
_DEFAULT_KEA6_CONFIG = {
    "Dhcp6": {
        "interfaces-config": {
            "interfaces": []
        },
        "control-socket": {
            "socket-type": "unix",
            "socket-name": "/var/run/kea/kea-dhcp6-ctrl.sock"
        },
        "lease-database": {
            "type": "memfile",
            "lfc-interval": 3600,
            "name": "/var/lib/kea/kea-leases6.csv"
        },
        "host-reservation-identifiers": ["duid"],
        "preferred-lifetime": 3000,
        "valid-lifetime": 4000,
        "option-data": [],
        "shared-networks": [],
        "subnet6": [],
        "loggers": [
            {
                "name": "kea-dhcp6",
                "output_options": [
                    {
                        "output": "/var/log/kea/kea-dhcp6.log",
                        "maxver": 8,
                        "maxsize": 204800,
                        "flush": True
                    }
                ],
                "severity": "INFO",
                "debuglevel": 0
            }
        ]
    }
}


from typing import Any, Callable, Dict, Optional, TypeVar, Union

def load_json(file_path: str, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Load and return JSON data from the specified file.

    Uses shared file locks to ensure safety. Returns `default` (the v4 Kea
    config skeleton unless a caller passes its own, e.g. the v6 skeleton) if
    the file does not exist or fails to decode.

    Args:
        file_path (str): The path to the JSON file to load.
        default (Optional[Dict[str, Any]]): Skeleton to fall back to. Defaults
            to the v4 skeleton for backwards compatibility with existing callers.

    Returns:
        Dict[str, Any]: The loaded JSON dictionary or default skeleton.
    """
    fallback = default if default is not None else _DEFAULT_KEA_CONFIG
    try:
        with open(file_path, "r") as file:
            fcntl.flock(file, fcntl.LOCK_SH)
            content = file.read()
            fcntl.flock(file, fcntl.LOCK_UN)
        return dict(json.loads(content))
    except json.JSONDecodeError:
        return dict(fallback)
    except FileNotFoundError:
        return dict(fallback)


def save_json(data: Dict[str, Any], file_path: str) -> None:
    """
    Save dict data to the specified file as formatted JSON.
    
    Creates necessary parent directories. Uses an exclusive file lock
    during the write process to ensure thread/process safety.

    Args:
        data (Dict[str, Any]): The dictionary data to write.
        file_path (str): The destination file path.
    """
    # Ensure parent directory exists
    parent = os.path.dirname(os.path.abspath(file_path))
    os.makedirs(parent, exist_ok=True)
    with open(file_path, "w") as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        json.dump(data, file, indent=2)
        fcntl.flock(file, fcntl.LOCK_UN)



# ── Process-wide, per-file locking for load→mutate→save cycles ──────────────
#
# fcntl.flock() (used inside load_json/save_json above) only guards the
# individual read or write syscall — it does nothing to stop two concurrent
# requests from both loading the same config, mutating their own in-memory
# copies, and then racing to save, silently discarding one of them (see
# AUDIT_FINDINGS.md 1.8). Waitress's default worker model is threaded, so a
# plain threading.Lock per resolved file path is enough to serialize the
# entire cycle within this process.

_file_locks: Dict[str, threading.Lock] = {}
_file_locks_guard = threading.Lock()

_F = TypeVar("_F", bound=Callable[..., Any])


def _get_file_lock(file_path: str) -> threading.Lock:
    """Return the (creating if necessary) lock associated with a config file's resolved path."""
    resolved = os.path.realpath(file_path)
    with _file_locks_guard:
        lock = _file_locks.get(resolved)
        if lock is None:
            lock = threading.Lock()
            _file_locks[resolved] = lock
        return lock


@contextmanager
def config_lock(file_path: str):
    """Context manager holding the process-wide lock for `file_path` for its duration."""
    lock = _get_file_lock(file_path)
    lock.acquire()
    try:
        yield
    finally:
        lock.release()


def with_config_lock(config_key: str = "DHCP_CONFIG_FILE", default: Optional[str] = None) -> Callable[[_F], _F]:
    """
    Route decorator: acquire the process-wide lock for `current_app.config[config_key]`
    (falling back to `default` if the key is absent) for the entire duration of the
    decorated view function, so its load→mutate→save cycle can't interleave with
    another request's.
    """
    def decorator(fn: _F) -> _F:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            from flask import current_app
            path = current_app.config.get(config_key, default) if default is not None else current_app.config[config_key]
            with config_lock(path):
                return fn(*args, **kwargs)
        return wrapper  # type: ignore[return-value]
    return decorator


def extract_log_file_from_config(config_file: str, default_fallback: str, dhcp_key: str = "Dhcp4", logger_name: str = "kea-dhcp4") -> str:
    """
    Attempts to read the Kea configuration file and extract the log file path
    from <dhcp_key> -> loggers -> output_options. Falls back to default_fallback.
    """
    config = load_json(config_file, default=_DEFAULT_KEA6_CONFIG if dhcp_key == "Dhcp6" else None)
    try:
        loggers = config.get(dhcp_key, {}).get("loggers", [])
        for logger in loggers:
            if logger.get("name") == logger_name:
                for opt in logger.get("output_options", []):
                    output_path = opt.get("output", "")
                    if output_path and output_path not in ("stdout", "stderr"):
                        return output_path
    except Exception:
        pass
    return default_fallback


def extract_log_file_from_config6(config_file: str, default_fallback: str) -> str:
    """extract_log_file_from_config(), scoped to the DHCPv6 config/logger."""
    return extract_log_file_from_config(config_file, default_fallback, dhcp_key="Dhcp6", logger_name="kea-dhcp6")


def bootstrap_config(config_file: str, backup_dir: str, default_config: Optional[Dict[str, Any]] = None) -> None:
    """
    Called at app startup. Creates the data directory and writes a minimal
    valid Kea config skeleton (the v4 skeleton unless `default_config` is
    given, e.g. the v6 skeleton) if the config file does not already exist.
    """
    try:
        os.makedirs(os.path.dirname(os.path.abspath(config_file)), exist_ok=True)
    except PermissionError:
        pass # In LIVE mode with system paths (/etc) we might not have permission, ignore it.

    try:
        os.makedirs(backup_dir, exist_ok=True)
    except PermissionError:
        pass

    if not os.path.exists(config_file):
        try:
            save_json(dict(default_config if default_config is not None else _DEFAULT_KEA_CONFIG), config_file)
        except PermissionError:
            pass # We can't write the default config, so we'll run read-only and fail on save


def bootstrap_config6(config_file: str, backup_dir: str) -> None:
    """bootstrap_config(), scoped to the DHCPv6 default skeleton."""
    bootstrap_config(config_file, backup_dir, default_config=_DEFAULT_KEA6_CONFIG)


def _config_identity(config_file: str) -> str:
    """
    Stable short identifier for a config file's full resolved path.

    Encoded into backup filenames so that restore can tell backups of *this*
    config_file apart from backups of some other config_file that happens to
    share the same basename in the same backup_dir (see AUDIT_FINDINGS.md 1.7
    — `dhcp_config_file` is fully operator/attacker-settable, so basename
    alone is not a safe way to scope a restore).
    """
    return hashlib.sha256(os.path.realpath(config_file).encode()).hexdigest()[:16]


def copy_file(config_file: str, backup_dir: str, restore: bool = False) -> Union[str, bool]:
    """
    Backup or restore the Kea DHCP configuration file.

    When `restore` is False, copies the `config_file` to `backup_dir` with a timestamp.
    When `restore` is True, finds the most recent backup in `backup_dir` that was
    made *for this same config_file* and copies it over `config_file`.

    Args:
        config_file (str): Path to the active Kea configuration file.
        backup_dir (str): Directory where backups are stored.
        restore (bool): Whether to perform a restore operation from a backup.

    Returns:
        Union[str, bool]: If not restoring, the path to the backup file created.
                          If restoring, True on success, False if no backup found.
    """
    filename = os.path.basename(config_file)
    identity = _config_identity(config_file)

    if restore:
        most_recent_backup = None
        largest_timestamp = None
        if not os.path.exists(backup_dir):
            print("Backup directory does not exist.")
            return False

        # Only consider backups that were made for *this* config_file (matched by
        # the identity fingerprint), never merely the newest ".bak." file in the
        # directory regardless of which config it belongs to.
        prefix = f"{filename}.{identity}.bak."
        for backup_file in os.listdir(backup_dir):
            if backup_file.startswith(prefix):
                try:
                    timestamp = int(backup_file[len(prefix):])
                except ValueError:
                    continue
                if largest_timestamp is None or timestamp > largest_timestamp:
                    most_recent_backup = os.path.join(backup_dir, backup_file)
                    largest_timestamp = timestamp

        if most_recent_backup:
            try:
                shutil.copy2(most_recent_backup, config_file)
                print(f"Successfully restored configuration from {most_recent_backup}")
                return True
            except Exception as e:
                print(f"Error copying file: {e}")
                raise
        else:
            print("No backup file found matching the current configuration to restore.")
            return False
    else:
        os.makedirs(backup_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        backup_name = os.path.join(backup_dir, f"{filename}.{identity}.bak.{timestamp}")
        try:
            shutil.copy2(config_file, backup_name)
            print(f"Successfully backed up configuration to {backup_name}")
            return backup_name
        except Exception as e:
            print(f"Error copying file: {e}")
            raise
