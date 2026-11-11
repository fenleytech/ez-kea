"""New-subnet ID allocation must not collide with IDs Kea assigned implicitly.

A config whose subnets carry no "id" (common in hand-written configs) still has
IDs at runtime: Kea numbers them on load and records them on every lease.
Treating a missing id as 0 handed the first new subnet ID 1, which the daemon
already used.
"""
from ez_kea.routes.dhcp4 import _next_subnet_id
from ez_kea.routes.dhcp6 import _next_subnet6_id


def test_v4_idless_subnets_in_shared_network_are_not_reused():
    config = {"Dhcp4": {"shared-networks": [{"name": "HOME", "subnet4": [
        {"subnet": "10.10.10.0/24"},
        {"subnet": "192.168.10.0/24"},
    ]}]}}
    assert _next_subnet_id(config) == 3


def test_v4_mixed_explicit_and_idless():
    config = {"Dhcp4": {
        "subnet4": [{"id": 5, "subnet": "10.0.0.0/24"}, {"subnet": "10.0.1.0/24"}],
        "shared-networks": [{"name": "A", "subnet4": [{"subnet": "10.0.2.0/24"}]}],
    }}
    assert _next_subnet_id(config) == 8


def test_v4_all_explicit_unchanged():
    config = {"Dhcp4": {"subnet4": [{"id": 1}, {"id": 7}]}}
    assert _next_subnet_id(config) == 8


def test_v4_empty_config():
    assert _next_subnet_id({"Dhcp4": {}}) == 1


def test_v6_idless_subnets_are_not_reused():
    config = {"Dhcp6": {
        "subnet6": [{"subnet": "2001:db8::/64"}],
        "shared-networks": [{"name": "B", "subnet6": [{"id": 2, "subnet": "2001:db8:1::/64"}]}],
    }}
    assert _next_subnet6_id(config) == 4
