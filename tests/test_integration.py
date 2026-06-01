"""Integration tests: full method pipelines with realistic device output."""

from unittest.mock import MagicMock

import pytest
from napalm.base.exceptions import CommandErrorException

from napalm_h3c_comware.comware import ComwareDriver


@pytest.fixture
def connected_device():
    """Device fixture with a mocked netmiko connection (device.device set)."""
    dev = ComwareDriver(
        "10.0.0.1",
        "admin",
        "password",
        timeout=100,
        optional_args={"fast_cli": False},
    )
    dev.device = MagicMock()
    return dev


class TestConnectionLifecycle:
    """Tests for open/close/context manager/is_alive."""

    def test_is_alive_when_connected(self, connected_device):
        connected_device.device.is_alive = MagicMock(return_value=True)
        assert connected_device.is_alive() == {"is_alive": True}

    def test_is_alive_when_disconnected(self, device):
        assert device.is_alive() == {"is_alive": False}

    def test_is_alive_returns_false_on_exception(self, connected_device):
        connected_device.device.is_alive = MagicMock(side_effect=Exception("timeout"))
        assert connected_device.is_alive() == {"is_alive": False}

    def test_send_command_raises_when_not_connected(self, device):
        with pytest.raises(CommandErrorException, match="not connected"):
            device.send_command("display version")

    def test_send_config_set_raises_when_not_connected(self, device):
        with pytest.raises(CommandErrorException, match="not connected"):
            device.send_config_set(["sysname test"])

    def test_find_prompt_raises_when_not_connected(self, device):
        with pytest.raises(CommandErrorException, match="not connected"):
            device.find_prompt()


class TestFactsIntegration:
    """Tests for get_facts() with realistic subsystem data."""

    def test_get_facts_assembles_all_subsystems(self, connected_device):
        connected_device._get_version = MagicMock(
            return_value={
                "os_version": "Release 6607",
                "vendor": "H3C",
                "uptime": 12345678,
                "model": "S6850-2C",
            }
        )
        connected_device.find_prompt = MagicMock(return_value="<core-sw>")
        connected_device._get_device_manuinfo = MagicMock(
            return_value=[
                {
                    "chassis_id": "1",
                    "slot_type": "Slot",
                    "slot_id": "1",
                    "device_name": "S6850-2C",
                    "serial_number": "SN123456",
                    "manufacturing_date": "2020-05-15",
                    "vendor_name": "H3C",
                    "mac_address": None,
                }
            ]
        )
        connected_device.get_interfaces = MagicMock(
            return_value={
                "GigabitEthernet1/0/1": {"is_enabled": True, "is_up": True},
                "GigabitEthernet1/0/2": {"is_enabled": True, "is_up": False},
            }
        )

        facts = connected_device.get_facts()

        assert facts["vendor"] == "H3C"
        assert facts["model"] == "S6850-2C"
        assert facts["hostname"] == "core-sw"
        assert facts["serial_number"] == "SN123456"
        assert facts["uptime"] == 12345678.0
        assert "GigabitEthernet1/0/1" in facts["interface_list"]

    def test_get_facts_handles_empty_serial(self, connected_device):
        connected_device._get_version = MagicMock(
            return_value={
                "os_version": "Release 6607",
                "vendor": "H3C",
                "uptime": 0,
                "model": "S6850-2C",
            }
        )
        connected_device.find_prompt = MagicMock(return_value="<sw>")
        connected_device._get_device_manuinfo = MagicMock(return_value=[])
        connected_device.get_interfaces = MagicMock(return_value={})

        facts = connected_device.get_facts()
        assert facts["serial_number"] == ""

    def test_get_facts_raises_on_collection_failure(self, connected_device):
        connected_device._get_version = MagicMock(side_effect=Exception("SSH timeout"))
        with pytest.raises(ValueError, match="Data collection failed"):
            connected_device.get_facts()


class TestCountersIntegration:
    """Tests for get_interfaces_counters() with raw device output."""

    def test_parses_counters_from_real_output(self, connected_device):
        connected_device.send_command = MagicMock(
            return_value=(
                "GigabitEthernet1/0/1 current state: UP\n"
                "Line protocol state: UP\n"
                "Input: 5000 packets, 250000 bytes\n"
                "  Unicast: 4000\n"
                "  Multicast: 800\n"
                "  Broadcast: 200\n"
                "  Total Error: 10\n"
                "  Discard: 5\n"
                "Output: 6000 packets, 300000 bytes\n"
                "  4800 unicast\n"
                "  900 multicast\n"
                "  300 broadcast\n"
                "  8 errors\n"
                "  2 discard\n"
            )
        )

        counters = connected_device.get_interfaces_counters()

        assert "GigabitEthernet1/0/1" in counters
        c = counters["GigabitEthernet1/0/1"]
        assert c["rx_octets"] == 250000
        assert c["tx_octets"] == 300000
        assert c["rx_errors"] == 10
        assert c["tx_errors"] == 8
        assert c["rx_unicast_packets"] == 4000
        assert c["tx_unicast_packets"] == 4800
        assert c["rx_multicast_packets"] == 800
        assert c["tx_multicast_packets"] == 900

    def test_counters_zero_when_stats_missing(self, connected_device):
        connected_device.send_command = MagicMock(
            return_value=("GigabitEthernet1/0/1 current state: UP\n" "Line protocol state: UP\n")
        )

        counters = connected_device.get_interfaces_counters()
        c = counters["GigabitEthernet1/0/1"]
        assert c["rx_errors"] == 0
        assert c["tx_errors"] == 0


class TestIPv6NeighborsIntegration:
    """Tests for get_ipv6_neighbors_table()."""

    def test_parses_ipv6_neighbors(self, connected_device):
        connected_device.send_command = MagicMock(
            return_value=(
                "IPv6 Address                   MAC Address        VLAN/Status      Interface\n"
                "2001:db8::1                    0012-3456-789a     Reach            Vlan-interface1\n"
                "fe80::201:2345:6789:abcd       0022-3344-5566     120 Stale        GigabitEthernet1/0/1\n"
            )
        )

        result = connected_device.get_ipv6_neighbors_table()
        assert len(result) == 2
        assert result[0]["ip"] == "2001:db8::1"
        assert result[0]["interface"] == "VLAN1"
        assert result[1]["age"] == 120.0
        assert result[1]["state"] == "Stale"

    def test_handles_empty_neighbor_table(self, connected_device):
        connected_device.send_command = MagicMock(
            return_value="IPv6 Address                   MAC Address        VLAN/Status      Interface\n"
        )
        assert connected_device.get_ipv6_neighbors_table() == []


class TestARPIntegration:
    """Tests for get_arp_table()."""

    def test_parses_arp_with_realistic_data(self, connected_device):
        connected_device._get_structured_output = MagicMock(
            return_value=[
                {"interface": "XGE1/0/1", "mac_address": "0012-3456-789a", "ip_address": "10.1.1.1", "aging": "1200"},
                {"interface": "XGE1/0/2", "mac_address": "00aa-bbcc-ddee", "ip_address": "10.1.1.2", "aging": "60"},
            ]
        )

        result = connected_device.get_arp_table()
        assert len(result) == 2
        assert result[0]["ip"] == "10.1.1.1"
        assert result[0]["interface"] == "Ten-GigabitEthernet1/0/1"
        assert result[0]["age"] == 1200.0

    def test_rejects_invalid_vrf_name(self, connected_device):
        with pytest.raises(ValueError, match="Invalid VRF name"):
            connected_device.get_arp_table(vrf="bad vrf name!")


class TestVLANIntegration:
    """Tests for get_vlans()."""

    def test_parses_vlans(self, connected_device):
        connected_device._get_structured_output = MagicMock(
            return_value=[
                {
                    "vlan_id": "1",
                    "name": "VLAN 0001",
                    "description": "VLAN 0001",
                    "interfaces": ["GigabitEthernet1/0/1", "GigabitEthernet1/0/2"],
                },
                {
                    "vlan_id": "100",
                    "name": "VLAN 0100",
                    "description": "Mgmt",
                    "interfaces": ["GigabitEthernet1/0/10"],
                },
            ]
        )

        result = connected_device.get_vlans()
        assert "1" in result
        assert "100" in result
        assert result["1"]["name"] == "VLAN 0001"
        # description overrides name when name starts with "VLAN " and desc does not
        assert result["100"]["name"] == "Mgmt"


class TestRunningConfigCache:
    """Tests for running config caching behavior."""

    def test_caches_running_config_between_parsers(self, connected_device):
        call_count = [0]

        def side_effect(cmd, *args, **kwargs):
            if cmd == "display current-configuration":
                call_count[0] += 1
                return (
                    "sysname core\n"
                    "ntp-service unicast-server 192.0.2.10\n"
                    "snmp-agent community read public\n"
                    "local-user admin class manage\n"
                    "#\n"
                )
            return ""

        connected_device.send_command = MagicMock(side_effect=side_effect)
        # Mock get_facts since get_snmp_information calls it internally
        connected_device.get_facts = MagicMock(return_value={"serial_number": ""})

        connected_device.get_ntp_servers()
        connected_device.get_snmp_information()
        connected_device.get_users()

        # All three should use the same cached config (only 1 CLI call)
        assert call_count[0] == 1

    def test_discard_config_invalidates_cache(self, connected_device):
        call_count = [0]

        def side_effect(cmd, *args, **kwargs):
            call_count[0] += 1
            return "ntp-service unicast-server 192.0.2.10\n#\n"

        connected_device.send_command = MagicMock(side_effect=side_effect)
        connected_device.load_merge_candidate(config="ntp-service server 1.1.1.1\n")
        connected_device.discard_config()

        connected_device.get_ntp_servers()
        connected_device.get_ntp_servers()  # second call should use cache

        assert call_count[0] == 1  # only 1 CLI call despite 2 get_ntp_servers calls


class TestEnvironmentIntegration:
    """Tests for get_environment() with subsystem mocks."""

    def test_environment_uses_cache(self, connected_device):
        connected_device._get_cpu = MagicMock(return_value={"slot 1 cpu 0": {"%usage": 15.0}})
        connected_device._get_memory = MagicMock(
            return_value={
                "summary": {"total_ram": 500000, "used_ram": 250000, "available_ram": 250000, "free_ratio": 50.0}
            }
        )
        connected_device._get_power = MagicMock(return_value={})
        connected_device._get_fan = MagicMock(return_value={})
        connected_device._get_temperature = MagicMock(return_value={})

        env1 = connected_device.get_environment(use_cache=False)
        env2 = connected_device.get_environment(use_cache=True)

        assert env1["memory"]["used_ram"] == 250000
        assert env2["memory"]["used_ram"] == 250000
        assert env1 is env2

    def test_clear_cache_forces_refresh(self, connected_device):
        connected_device._get_cpu = MagicMock(return_value={"slot 1 cpu 0": {"%usage": 10.0}})
        connected_device._get_memory = MagicMock(
            return_value={
                "summary": {"total_ram": 500000, "used_ram": 100000, "available_ram": 400000, "free_ratio": 80.0}
            }
        )
        connected_device._get_power = MagicMock(return_value={})
        connected_device._get_fan = MagicMock(return_value={})
        connected_device._get_temperature = MagicMock(return_value={})

        env1 = connected_device.get_environment(use_cache=False)
        connected_device.clear_cache()
        env2 = connected_device.get_environment(use_cache=False)

        assert env1 is not env2


class TestErrorHandling:
    """Tests for consistent error handling across methods."""

    def test_get_interfaces_ip_raises_command_error(self, connected_device):
        connected_device._get_structured_output = MagicMock(side_effect=Exception("CLI failed"))
        with pytest.raises(CommandErrorException, match="Failed to execute"):
            connected_device.get_interfaces_ip()

    def test_get_mac_move_table_raises_command_error(self, connected_device):
        connected_device._get_structured_output = MagicMock(side_effect=Exception("CLI failed"))
        with pytest.raises(CommandErrorException, match="Failed to execute"):
            connected_device.get_mac_address_move_table()

    def test_ping_validation_rejects_invalid_input(self, device):
        with pytest.raises(ValueError, match="Invalid ping destination"):
            device.ping("192.0.2.1; rm -rf /")

    def test_traceroute_rejects_vrf(self, device):
        with pytest.raises(NotImplementedError, match="VRF-aware traceroute"):
            device.traceroute("8.8.8.8", vrf="MGMT")

    def test_get_config_rejects_invalid_retrieve(self, device):
        with pytest.raises(ValueError, match="Invalid retrieve value"):
            device.get_config(retrieve="archive")


class TestMACTables:
    """Tests for get_mac_address_table with explicit move_table parameter."""

    def test_mac_table_standalone_without_move_data(self, connected_device):
        connected_device._get_structured_output = MagicMock(
            return_value=[
                {
                    "mac_address": "0012-3456-789a",
                    "vlan": "10",
                    "state": "dynamic",
                    "interface": "GigabitEthernet1/0/1",
                }
            ]
        )

        result = connected_device.get_mac_address_table()

        assert result[0]["moves"] == -1
        assert result[0]["last_move"] == -1.0

    def test_mac_table_with_explicit_move_data(self, connected_device):
        connected_device._get_structured_output = MagicMock(
            return_value=[
                {
                    "mac_address": "0012-3456-789a",
                    "vlan": "10",
                    "state": "dynamic",
                    "interface": "GigabitEthernet1/0/1",
                }
            ]
        )

        result = connected_device.get_mac_address_table(
            move_table=[
                {
                    "mac": "00:12:34:56:78:9A",
                    "vlan": 10,
                    "current_port": "GigabitEthernet1/0/1",
                    "source_port": "GigabitEthernet1/0/2",
                    "last_move": "2024-01-02 03:04:05",
                    "moves": 7,
                }
            ]
        )

        assert result[0]["moves"] == 7
        assert result[0]["last_move"] > 0


class TestBGPIntegration:
    """Tests for BGP with parallel peer detail collection."""

    def test_bgp_parallel_peer_details(self, connected_device):
        responses = {
            "display bgp peer": (
                "BGP local router ID : 10.1.1.1\n"
                "Local AS number : 65001\n"
                "Total number of peers : 2\n"
                "Peer        Remote-AS MsgRcvd MsgSent  TblVer  InQ  OutQ Up/Down       State/PfxRcd\n"
                "2.2.2.2     65002     12345   12344    32      0    0    00:35:27      Established/10\n"
                "3.3.3.3     65003     0       0        0       0    0    00:00:12      Idle\n"
            ),
            "display bgp peer 2.2.2.2": (
                "BGP peer is 2.2.2.2, remote AS 65002\n"
                " BGP version 4, remote router ID 2.2.2.22\n"
                " Advertised total routes: 5\n"
            ),
            "display bgp peer 3.3.3.3": (
                "BGP peer is 3.3.3.3, remote AS 65003\n" " BGP version 4, remote router ID 3.3.3.33\n"
            ),
        }

        def side_effect(cmd):
            return responses.get(cmd, "")

        connected_device.send_command = MagicMock(side_effect=side_effect)
        result = connected_device.get_bgp_neighbors()

        peers = result["global"]["peers"]
        assert len(peers) == 2
        assert peers["2.2.2.2"]["remote_id"] == "2.2.2.22"
        assert peers["2.2.2.2"]["address_family"]["ipv4 unicast"]["sent_prefixes"] == 5
        assert peers["3.3.3.3"]["remote_id"] == "3.3.3.33"
        assert peers["3.3.3.3"]["is_up"] is False

    def test_bgp_empty_output(self, connected_device):
        connected_device.send_command = MagicMock(return_value="")
        assert connected_device.get_bgp_neighbors() == {}
