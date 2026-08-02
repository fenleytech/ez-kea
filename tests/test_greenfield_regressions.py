# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
Regressions found by deploying EZ-KEA from scratch onto a clean Ubuntu 24.04
box running ISC's own Kea 3.2 packages (`isc-kea-dhcp4`/`isc-kea-dhcp6` from
Cloudsmith).

Every test here corresponds to something that was actually broken on that box,
not to a hypothetical. The common thread is that packaged Kea does not look
like the sandbox EZ-KEA generates for itself: /etc/kea is 0750 _kea:_kea, the
binaries are 0750 _kea:_kea, `keactrl` does not exist at all, and the shipped
config uses a bare relative `socket-name`.
"""
import json
import os
import stat

import pytest

from ez_kea.core.config_manager import (
    BackupError,
    ConfigAccessError,
    copy_file,
    load_json,
    prune_backups,
    save_kea_config,
)
from ez_kea.core.kea_ctrl import KEA_DEFAULT_SOCKET_DIR, find_unix_socket_path


# ── An unreadable config must never masquerade as an empty one ───────────────

def test_load_json_raises_rather_than_returning_skeleton_when_unreadable(tmp_path):
    """
    A config we cannot read must raise, not fall back to the empty skeleton.

    Falling back is the dangerous option: the UI would render as though the
    server had no subnets, and the operator's next save would overwrite their
    real config with that skeleton.
    """
    cfg = tmp_path / "kea-dhcp4.conf"
    cfg.write_text(json.dumps({"Dhcp4": {"subnet4": [{"id": 1, "subnet": "10.0.0.0/24"}]}}))
    cfg.chmod(0o000)

    if os.access(cfg, os.R_OK):  # running as root ignores the mode bits
        pytest.skip("cannot test unreadable files as root")

    with pytest.raises(ConfigAccessError) as excinfo:
        load_json(str(cfg))

    # The message has to tell the operator what to actually do about it.
    assert "group" in str(excinfo.value).lower()


def test_load_json_still_falls_back_for_missing_files(tmp_path):
    """The pre-existing fallback behaviour must survive the change above."""
    assert "Dhcp4" in load_json(str(tmp_path / "nope.conf"))


def test_load_json_raises_rather_than_returning_skeleton_for_corrupt_files(tmp_path):
    """
    An existing file that fails to parse must raise for exactly the same
    reason the unreadable-file test above does: silently handing back the
    empty skeleton would make the UI look like the server has no subnets,
    and the operator's next save would overwrite their real config with
    that skeleton. This is precisely what happened on the same greenfield
    box this file is named for — ISC's shipped kea-dhcp4.conf is full of
    "//" comments, which used to trip this exact fallback and got silently
    persisted over on the very first settings save. See AUDIT_FINDINGS.md,
    2026-08-02.
    """
    corrupt = tmp_path / "corrupt.conf"
    corrupt.write_text("{not json at all")
    with pytest.raises(ConfigAccessError):
        load_json(str(corrupt))


# ── Every Kea config write takes a backup first ──────────────────────────────

def test_save_kea_config_backs_up_previous_contents(tmp_path):
    """
    "Backs up your Kea configs before it writes" — the README's headline safety
    claim. It was true only of the explicit Backup button; all 23 other write
    paths went straight to save_json().
    """
    cfg = tmp_path / "kea-dhcp4.conf"
    backups = tmp_path / "backups"
    cfg.write_text(json.dumps({"Dhcp4": {"valid-lifetime": 3600}}))

    save_kea_config({"Dhcp4": {"valid-lifetime": 7200}}, str(cfg), str(backups))

    assert json.loads(cfg.read_text())["Dhcp4"]["valid-lifetime"] == 7200
    written = list(backups.iterdir())
    assert len(written) == 1, "expected exactly one pre-write backup"
    assert json.loads(written[0].read_text())["Dhcp4"]["valid-lifetime"] == 3600, \
        "the backup must hold the PREVIOUS contents, not the new ones"


def test_save_kea_config_aborts_the_write_when_the_backup_fails(tmp_path):
    """
    A failed backup must abort the write. Writing anyway would break exactly
    the guarantee the operator is leaning on during a bad edit.
    """
    cfg = tmp_path / "kea-dhcp4.conf"
    cfg.write_text(json.dumps({"Dhcp4": {"valid-lifetime": 3600}}))

    blocked = tmp_path / "backups"
    blocked.mkdir()
    blocked.chmod(0o500)  # readable + traversable, not writable

    if os.access(blocked, os.W_OK):  # root again
        pytest.skip("cannot test unwritable directories as root")

    try:
        with pytest.raises(BackupError):
            save_kea_config({"Dhcp4": {"valid-lifetime": 7200}}, str(cfg), str(blocked))
        assert json.loads(cfg.read_text())["Dhcp4"]["valid-lifetime"] == 3600, \
            "config must be untouched when its backup could not be taken"
    finally:
        blocked.chmod(0o700)


def test_save_kea_config_creates_a_first_file_without_needing_a_backup(tmp_path):
    """Bootstrapping a config that does not exist yet has nothing to back up."""
    cfg = tmp_path / "new.conf"
    save_kea_config({"Dhcp4": {}}, str(cfg), str(tmp_path / "backups"))
    assert cfg.is_file()


def test_prune_backups_keeps_only_the_newest_and_is_scoped_per_config(tmp_path):
    """
    Backing up on every write means retention matters now. Pruning must also
    stay scoped to one config's own history.
    """
    backups = tmp_path / "backups"
    backups.mkdir()
    mine = tmp_path / "kea-dhcp4.conf"
    mine.write_text("{}")
    theirs = tmp_path / "other" / "kea-dhcp4.conf"
    theirs.parent.mkdir()
    theirs.write_text("{}")

    for stamp in range(20260101000000, 20260101000005):
        for target in (mine, theirs):
            from ez_kea.core.config_manager import _config_identity
            name = f"{target.name}.{_config_identity(str(target))}.bak.{stamp}"
            (backups / name).write_text("{}")

    prune_backups(str(mine), str(backups), keep=2)

    from ez_kea.core.config_manager import _config_identity
    remaining = os.listdir(backups)
    mine_left = [f for f in remaining if _config_identity(str(mine)) in f]
    theirs_left = [f for f in remaining if _config_identity(str(theirs)) in f]

    assert len(mine_left) == 2, "should keep exactly the newest 2"
    assert "20260101000004" in " ".join(mine_left)
    assert len(theirs_left) == 5, "pruning one config must not touch another's backups"


# ── Restore must not chmod a file it does not own ────────────────────────────

def test_restore_does_not_require_ownership_of_the_config(tmp_path):
    """
    copy_file(restore=True) used shutil.copy2(), which chmods the destination.
    chmod requires ownership, and packaged Kea owns /etc/kea/kea-dhcp4.conf as
    _kea — so restore raised EPERM *after* writing the contents, reporting a
    500 for a restore that had actually succeeded.

    Proxy for that here: a destination whose mode differs from the backup's
    must be restorable, and must keep its own mode afterwards.
    """
    backups = tmp_path / "backups"
    backups.mkdir()
    cfg = tmp_path / "kea-dhcp4.conf"

    cfg.write_text(json.dumps({"Dhcp4": {"valid-lifetime": 3600}}))
    cfg.chmod(0o660)
    copy_file(str(cfg), str(backups))

    cfg.write_text(json.dumps({"Dhcp4": {"valid-lifetime": 9999}}))
    cfg.chmod(0o640)

    assert copy_file(str(cfg), str(backups), restore=True) is True
    assert json.loads(cfg.read_text())["Dhcp4"]["valid-lifetime"] == 3600
    assert stat.S_IMODE(cfg.stat().st_mode) == 0o640, \
        "restore must replace contents only, never the destination's mode"


# ── ISC's packaged config uses a bare relative socket-name ───────────────────

def test_relative_socket_name_resolves_against_keas_runtime_dir():
    """
    ISC's shipped kea-dhcp4.conf contains exactly this. Passed through
    verbatim it made socket.connect() look in EZ-KEA's cwd, so the
    control-socket reload could never work on the one platform where it is the
    only option left (Kea 3.2 ships no keactrl at all).
    """
    config = {"Dhcp4": {"control-socket": {"socket-type": "unix",
                                           "socket-name": "kea4-ctrl-socket"}}}
    assert find_unix_socket_path(config, "Dhcp4") == \
        os.path.join(KEA_DEFAULT_SOCKET_DIR, "kea4-ctrl-socket")


def test_absolute_socket_name_is_left_alone():
    config = {"Dhcp4": {"control-sockets": [{"socket-type": "unix",
                                             "socket-name": "/var/run/kea/custom.sock"}]}}
    assert find_unix_socket_path(config, "Dhcp4") == "/var/run/kea/custom.sock"


def test_no_socket_configured_still_reports_none():
    assert find_unix_socket_path({"Dhcp4": {}}, "Dhcp4") == ""
