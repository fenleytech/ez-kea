"""
tests/test_dhcp_options.py

Unit tests for DHCP option-data management: global options (DNS, NTP, domain-name),
per-subnet options, renew/rebind timers, and round-trip JSON integrity.
All tests operate on in-memory config dicts — no file I/O required.
"""
import pytest
import json
import copy

# ── Helpers that mirror what routes/system.py and routes/options.py do ──────

def _apply_global_options(config, dns="", ntp="", domain=""):
    """Mirror of save_global_settings global option-data logic."""
    dhcp4 = config.setdefault("Dhcp4", {})
    MANAGED = {"domain-name-servers": dns, "ntp-servers": ntp, "domain-name": domain}
    existing = [o for o in dhcp4.get("option-data", []) if o.get("name") not in MANAGED]
    for name, data in MANAGED.items():
        if data.strip():
            existing.append({"name": name, "data": data.strip()})
    dhcp4["option-data"] = existing
    return config


def _set_subnet_option(config, subnet_cidr, name, data):
    """Mirror of manage_standalone_subnet4_options POST logic."""
    for s in config.get("Dhcp4", {}).get("subnet4", []):
        if s.get("subnet") == subnet_cidr:
            opts = s.setdefault("option-data", [])
            for opt in opts:
                if opt.get("name") == name:
                    opt["data"] = data
                    return config
            opts.append({"name": name, "data": data})
            return config
    raise KeyError(f"Subnet {subnet_cidr} not found")


def _delete_subnet_option(config, subnet_cidr, name):
    """Mirror of delete_standalone_subnet4_option logic."""
    for s in config.get("Dhcp4", {}).get("subnet4", []):
        if s.get("subnet") == subnet_cidr:
            s["option-data"] = [o for o in s.get("option-data", []) if o.get("name") != name]
    return config


def _set_timers(config, valid=None, renew=None, rebind=None):
    """Mirror of save_global_settings timer logic."""
    dhcp4 = config.setdefault("Dhcp4", {})
    if valid is not None: dhcp4["valid-lifetime"] = int(valid)
    if renew is not None: dhcp4["renew-timer"] = int(renew)
    else: dhcp4.pop("renew-timer", None)
    if rebind is not None: dhcp4["rebind-timer"] = int(rebind)
    else: dhcp4.pop("rebind-timer", None)
    return config


def _set_subnet6_option(config, subnet_cidr, name, data):
    """Mirror of manage_standalone_subnet6_options POST logic."""
    for s in config.get("Dhcp6", {}).get("subnet6", []):
        if s.get("subnet") == subnet_cidr:
            opts = s.setdefault("option-data", [])
            for opt in opts:
                if opt.get("name") == name:
                    opt["data"] = data
                    return config
            opts.append({"name": name, "data": data})
            return config
    raise KeyError(f"Subnet {subnet_cidr} not found")


def _delete_subnet6_option(config, subnet_cidr, name):
    """Mirror of delete_standalone_subnet6_option logic."""
    for s in config.get("Dhcp6", {}).get("subnet6", []):
        if s.get("subnet") == subnet_cidr:
            s["option-data"] = [o for o in s.get("option-data", []) if o.get("name") != name]
    return config


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def base_config():
    return {
        "Dhcp4": {
            "valid-lifetime": 4000,
            "subnet4": [
                {
                    "id": 10,
                    "subnet": "172.30.110.0/24",
                    "pools": [{"pool": "172.30.110.100 - 172.30.110.101"}],
                    "reservations": []
                },
                {
                    "id": 20,
                    "subnet": "172.30.120.0/24",
                    "pools": [{"pool": "172.30.120.100 - 172.30.120.200"}],
                    "reservations": []
                }
            ]
        }
    }


# ── Global Option Tests ───────────────────────────────────────────────────────

class TestGlobalOptions:

    def test_set_dns_servers(self, base_config):
        cfg = _apply_global_options(base_config, dns="1.1.1.1, 8.8.8.8")
        opts = {o["name"]: o["data"] for o in cfg["Dhcp4"]["option-data"]}
        assert opts["domain-name-servers"] == "1.1.1.1, 8.8.8.8"

    def test_set_ntp_servers(self, base_config):
        cfg = _apply_global_options(base_config, ntp="0.pool.ntp.org")
        opts = {o["name"]: o["data"] for o in cfg["Dhcp4"]["option-data"]}
        assert opts["ntp-servers"] == "0.pool.ntp.org"

    def test_set_domain_name(self, base_config):
        cfg = _apply_global_options(base_config, domain="home.local")
        opts = {o["name"]: o["data"] for o in cfg["Dhcp4"]["option-data"]}
        assert opts["domain-name"] == "home.local"

    def test_all_global_options_together(self, base_config):
        cfg = _apply_global_options(base_config, dns="1.1.1.1", ntp="pool.ntp.org", domain="corp.local")
        opts = {o["name"]: o["data"] for o in cfg["Dhcp4"]["option-data"]}
        assert opts["domain-name-servers"] == "1.1.1.1"
        assert opts["ntp-servers"] == "pool.ntp.org"
        assert opts["domain-name"] == "corp.local"

    def test_overwrite_existing_global_option(self, base_config):
        cfg = _apply_global_options(base_config, dns="1.1.1.1")
        cfg = _apply_global_options(cfg, dns="8.8.8.8, 8.8.4.4")
        dns_entries = [o for o in cfg["Dhcp4"]["option-data"] if o["name"] == "domain-name-servers"]
        assert len(dns_entries) == 1, "Should not duplicate option on overwrite"
        assert dns_entries[0]["data"] == "8.8.8.8, 8.8.4.4"

    def test_clear_global_option_with_empty_string(self, base_config):
        cfg = _apply_global_options(base_config, dns="1.1.1.1", ntp="pool.ntp.org")
        cfg = _apply_global_options(cfg, dns="", ntp="")  # Clear both
        names = [o["name"] for o in cfg["Dhcp4"]["option-data"]]
        assert "domain-name-servers" not in names
        assert "ntp-servers" not in names

    def test_unmanaged_options_preserved(self, base_config):
        """Options set elsewhere (e.g. custom ones) should not be wiped by global save."""
        base_config["Dhcp4"]["option-data"] = [{"name": "routers", "data": "192.168.1.1"}]
        cfg = _apply_global_options(base_config, dns="1.1.1.1")
        names = [o["name"] for o in cfg["Dhcp4"]["option-data"]]
        assert "routers" in names
        assert "domain-name-servers" in names


# ── Per-Subnet Option Tests ───────────────────────────────────────────────────

class TestSubnetOptions:

    def test_set_option_on_subnet(self, base_config):
        cfg = _set_subnet_option(base_config, "172.30.110.0/24", "routers", "172.30.110.1")
        subnet = next(s for s in cfg["Dhcp4"]["subnet4"] if s["subnet"] == "172.30.110.0/24")
        assert subnet["option-data"][0] == {"name": "routers", "data": "172.30.110.1"}

    def test_overwrite_subnet_option(self, base_config):
        cfg = _set_subnet_option(base_config, "172.30.110.0/24", "routers", "172.30.110.1")
        cfg = _set_subnet_option(cfg, "172.30.110.0/24", "routers", "172.30.110.254")
        subnet = next(s for s in cfg["Dhcp4"]["subnet4"] if s["subnet"] == "172.30.110.0/24")
        routers = [o for o in subnet["option-data"] if o["name"] == "routers"]
        assert len(routers) == 1
        assert routers[0]["data"] == "172.30.110.254"

    def test_multiple_options_on_subnet(self, base_config):
        cfg = _set_subnet_option(base_config, "172.30.110.0/24", "routers", "172.30.110.1")
        cfg = _set_subnet_option(cfg, "172.30.110.0/24", "domain-name-servers", "1.1.1.1")
        subnet = next(s for s in cfg["Dhcp4"]["subnet4"] if s["subnet"] == "172.30.110.0/24")
        assert len(subnet["option-data"]) == 2

    def test_delete_subnet_option(self, base_config):
        cfg = _set_subnet_option(base_config, "172.30.110.0/24", "routers", "172.30.110.1")
        cfg = _set_subnet_option(cfg, "172.30.110.0/24", "domain-name-servers", "1.1.1.1")
        cfg = _delete_subnet_option(cfg, "172.30.110.0/24", "routers")
        subnet = next(s for s in cfg["Dhcp4"]["subnet4"] if s["subnet"] == "172.30.110.0/24")
        names = [o["name"] for o in subnet["option-data"]]
        assert "routers" not in names
        assert "domain-name-servers" in names

    def test_set_acs_url_option(self, base_config):
        """Test for TR-069 ACS URL (typically vendor-encapsulated-options or vivso)."""
        acs_url = "http://acs.example.com/cwmp"
        cfg = _set_subnet_option(base_config, "172.30.110.0/24", "vendor-encapsulated-options", acs_url)
        subnet = next(s for s in cfg["Dhcp4"]["subnet4"] if s["subnet"] == "172.30.110.0/24")
        opt = next(o for o in subnet["option-data"] if o["name"] == "vendor-encapsulated-options")
        assert opt["data"] == acs_url

    def test_delete_nonexistent_option_is_safe(self, base_config):
        """Deleting an option that doesn't exist should not raise."""
        cfg = _delete_subnet_option(base_config, "172.30.110.0/24", "nonexistent-option")
        # Should not raise, subnet option-data should be absent or empty
        subnet = next(s for s in cfg["Dhcp4"]["subnet4"] if s["subnet"] == "172.30.110.0/24")
        assert subnet.get("option-data", []) == []

    def test_options_isolated_between_subnets(self, base_config):
        cfg = _set_subnet_option(base_config, "172.30.110.0/24", "routers", "172.30.110.1")
        s20 = next(s for s in cfg["Dhcp4"]["subnet4"] if s["subnet"] == "172.30.120.0/24")
        assert s20.get("option-data", []) == []

    def test_unknown_subnet_raises(self, base_config):
        with pytest.raises(KeyError):
            _set_subnet_option(base_config, "10.0.0.0/24", "routers", "10.0.0.1")


# ── Per-Subnet6 Option Tests (DHCPv6) ────────────────────────────────────────

@pytest.fixture
def base_config6():
    return {
        "Dhcp6": {
            "valid-lifetime": 4000,
            "preferred-lifetime": 3000,
            "subnet6": [
                {
                    "id": 10,
                    "subnet": "2001:db8:110::/64",
                    "pools": [{"pool": "2001:db8:110::100 - 2001:db8:110::200"}],
                    "reservations": []
                },
                {
                    "id": 20,
                    "subnet": "2001:db8:120::/64",
                    "pools": [{"pool": "2001:db8:120::100 - 2001:db8:120::200"}],
                    "reservations": []
                }
            ]
        }
    }


class TestSubnet6Options:

    def test_set_option_on_subnet6(self, base_config6):
        cfg = _set_subnet6_option(base_config6, "2001:db8:110::/64", "dns-servers", "2001:4860:4860::8888")
        subnet = next(s for s in cfg["Dhcp6"]["subnet6"] if s["subnet"] == "2001:db8:110::/64")
        assert subnet["option-data"][0] == {"name": "dns-servers", "data": "2001:4860:4860::8888"}

    def test_overwrite_subnet6_option(self, base_config6):
        cfg = _set_subnet6_option(base_config6, "2001:db8:110::/64", "dns-servers", "2001:4860:4860::8888")
        cfg = _set_subnet6_option(cfg, "2001:db8:110::/64", "dns-servers", "2001:4860:4860::8844")
        subnet = next(s for s in cfg["Dhcp6"]["subnet6"] if s["subnet"] == "2001:db8:110::/64")
        dns_entries = [o for o in subnet["option-data"] if o["name"] == "dns-servers"]
        assert len(dns_entries) == 1
        assert dns_entries[0]["data"] == "2001:4860:4860::8844"

    def test_multiple_options_on_subnet6(self, base_config6):
        cfg = _set_subnet6_option(base_config6, "2001:db8:110::/64", "dns-servers", "2001:4860:4860::8888")
        cfg = _set_subnet6_option(cfg, "2001:db8:110::/64", "domain-search", "home.local")
        subnet = next(s for s in cfg["Dhcp6"]["subnet6"] if s["subnet"] == "2001:db8:110::/64")
        assert len(subnet["option-data"]) == 2

    def test_delete_subnet6_option(self, base_config6):
        cfg = _set_subnet6_option(base_config6, "2001:db8:110::/64", "dns-servers", "2001:4860:4860::8888")
        cfg = _set_subnet6_option(cfg, "2001:db8:110::/64", "domain-search", "home.local")
        cfg = _delete_subnet6_option(cfg, "2001:db8:110::/64", "dns-servers")
        subnet = next(s for s in cfg["Dhcp6"]["subnet6"] if s["subnet"] == "2001:db8:110::/64")
        names = [o["name"] for o in subnet["option-data"]]
        assert "dns-servers" not in names
        assert "domain-search" in names

    def test_options_isolated_between_subnet6s(self, base_config6):
        cfg = _set_subnet6_option(base_config6, "2001:db8:110::/64", "dns-servers", "2001:4860:4860::8888")
        s20 = next(s for s in cfg["Dhcp6"]["subnet6"] if s["subnet"] == "2001:db8:120::/64")
        assert s20.get("option-data", []) == []

    def test_unknown_subnet6_raises(self, base_config6):
        with pytest.raises(KeyError):
            _set_subnet6_option(base_config6, "2001:db8:999::/64", "dns-servers", "2001:4860:4860::8888")


# ── Timer Tests ───────────────────────────────────────────────────────────────

class TestTimers:

    def test_set_valid_lifetime(self, base_config):
        cfg = _set_timers(base_config, valid=7200)
        assert cfg["Dhcp4"]["valid-lifetime"] == 7200

    def test_set_renew_and_rebind(self, base_config):
        cfg = _set_timers(base_config, valid=4000, renew=1000, rebind=2000)
        assert cfg["Dhcp4"]["renew-timer"] == 1000
        assert cfg["Dhcp4"]["rebind-timer"] == 2000

    def test_clear_optional_timers(self, base_config):
        cfg = _set_timers(base_config, valid=4000, renew=1000, rebind=2000)
        cfg = _set_timers(cfg, valid=4000)  # No renew/rebind → should be removed
        assert "renew-timer" not in cfg["Dhcp4"]
        assert "rebind-timer" not in cfg["Dhcp4"]

    def test_json_roundtrip(self, base_config):
        """Config should survive json.dumps/loads without mutation."""
        cfg = _apply_global_options(base_config, dns="1.1.1.1", ntp="pool.ntp.org")
        cfg = _set_timers(cfg, valid=3600, renew=900, rebind=1800)
        reloaded = json.loads(json.dumps(cfg))
        assert reloaded["Dhcp4"]["valid-lifetime"] == 3600
        assert reloaded["Dhcp4"]["renew-timer"] == 900
        opts = {o["name"]: o["data"] for o in reloaded["Dhcp4"]["option-data"]}
        assert opts["domain-name-servers"] == "1.1.1.1"
