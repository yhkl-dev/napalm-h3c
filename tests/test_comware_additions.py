import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from napalm_h3c_comware.utils.helpers import strptime


class TestEnvironmentAndLldpRegressions:
    def test_get_environment_filters_summary_cpu_entry(self, device):
        device._get_cpu = MagicMock(return_value={"%usage": 0, "slot 1 cpu 0": {"%usage": 23.0}})
        device._get_memory = MagicMock(return_value={"available_ram": 100, "used_ram": 50})
        device._get_power = MagicMock(return_value={})
        device._get_fan = MagicMock(return_value={})
        device._get_temperature = MagicMock(return_value={})

        result = device.get_environment(use_cache=False)

        assert result["cpu"] == {0: {"%usage": 23.0}}

    def test_get_environment_raises_on_subsystem_failure(self, device):
        device._get_cpu = MagicMock(side_effect=RuntimeError("cpu failed"))
        device._get_memory = MagicMock(return_value={"available_ram": 100, "used_ram": 50})
        device._get_power = MagicMock(return_value={})
        device._get_fan = MagicMock(return_value={})
        device._get_temperature = MagicMock(return_value={})

        with pytest.raises(RuntimeError, match="Failed to collect environment data"):
            device.get_environment(use_cache=False)

        assert device._env_cache is None

    def test_lldp_detail_joins_list_description(self, device):
        device._get_structured_output.return_value = [
            {
                "local_interface": "GigabitEthernet1/0/1",
                "remote_port": "Eth1",
                "remote_port_desc": "server-uplink",
                "remote_chassis_id": "0011-2233-4455",
                "remote_system_name": "leaf-01",
                "remote_system_desc": ["H3C", "Comware", "Switch"],
                "remote_system_capab": "bridge,router",
                "remote_system_enabled_capab": "bridge",
            }
        ]

        result = device.get_lldp_neighbors_detail()

        assert result["GigabitEthernet1/0/1"][0]["remote_system_description"] == "H3C Comware Switch"


class TestConfigWorkflow:
    def test_load_merge_candidate_and_compare(self, device):
        device.load_merge_candidate(config="ntp-service server 1.1.1.1\n")
        assert device.get_config(retrieve="candidate")["candidate"] == "ntp-service server 1.1.1.1\n"

        device.send_command = MagicMock(return_value="sysname current-sw\n#\n")
        diff = device.compare_config()
        assert "ntp-service server 1.1.1.1" in diff

    def test_load_replace_candidate_from_file(self, device, tmp_path: Path):
        candidate_file = tmp_path / "candidate.cfg"
        candidate_file.write_text("sysname replacement-sw\n#\n")

        device.load_replace_candidate(filename=str(candidate_file))

        assert device.get_config(retrieve="candidate")["candidate"] == "sysname replacement-sw\n#\n"

    def test_compare_config_for_replace_candidate(self, device):
        device.send_command = MagicMock(return_value="sysname core-sw\n#\n")

        device.load_replace_candidate(config="sysname replacement-sw\n#\n")
        diff = device.compare_config()

        assert "replacement-sw" in diff

    def test_discard_config_clears_candidate(self, device):
        device.load_merge_candidate(config="snmp-agent sys-info contact NOC\n")

        device.discard_config()

        assert device.get_config(retrieve="candidate")["candidate"] == ""
        assert device.compare_config() == ""

    def test_load_merge_candidate_requires_input(self, device):
        with pytest.raises(Exception, match="filename or config must be provided"):
            device.load_merge_candidate()

    def test_load_replace_candidate_requires_input(self, device):
        with pytest.raises(Exception, match="filename or config must be provided"):
            device.load_replace_candidate()

    def test_commit_config_for_merge_candidate(self, device):
        device.device = MagicMock()
        device.send_command = MagicMock(return_value="Configuration is saved.")
        device.load_merge_candidate(config="interface LoopBack1\n ip address 10.0.0.1 32\n")

        device.commit_config()

        device.device.send_config_set.assert_called_once_with(["interface LoopBack1", "ip address 10.0.0.1 32"])
        device.send_command.assert_any_call("save force backup-before-merge.cfg safely")
        device.send_command.assert_any_call("save force")
        assert device.get_config(retrieve="candidate")["candidate"] == ""

    def test_commit_config_rejects_replace_candidate(self, device):
        device.load_replace_candidate(config="sysname replacement-sw\n")

        with pytest.raises(Exception, match="replace commit is not yet supported"):
            device.commit_config()

        assert device.get_config(retrieve="candidate")["candidate"] == "sysname replacement-sw\n"

    def test_commit_config_rejects_commit_message_and_revert_timer(self, device):
        with pytest.raises(NotImplementedError, match="commit messages"):
            device.commit_config(message="change-ticket")

        with pytest.raises(NotImplementedError, match="revert timers"):
            device.commit_config(revert_in=300)

    def test_rollback_from_merge_backup(self, device):
        device.device = MagicMock()
        calls = []

        def side_effect(cmd):
            calls.append(cmd)
            if cmd == "rollback configuration to file backup-before-merge.cfg":
                return "Configuration is saved."
            if cmd == "save force":
                return "Configuration is saved."
            raise Exception("not found")

        device.send_command = MagicMock(side_effect=side_effect)
        device.rollback()

        assert "rollback configuration to file backup-before-merge.cfg" in calls
        assert calls[-1] == "save force"

    def test_rollback_fallback_to_replace_backup(self, device):
        device.device = MagicMock()
        calls = []

        def side_effect(cmd):
            calls.append(cmd)
            if "backup-before-merge" in cmd:
                raise Exception("not found")
            if cmd == "rollback configuration to file backup-before-replace.cfg":
                return "Configuration is saved."
            return "Configuration is saved."

        device.send_command = MagicMock(side_effect=side_effect)
        device.rollback()

        assert "rollback configuration to file backup-before-replace.cfg" in calls
        assert calls[-1] == "save force"

    def test_rollback_prefers_most_recent_backup(self, device):
        device.device = MagicMock()
        device._last_backup_file = "backup-before-replace.cfg"
        calls = []

        def rollback_side_effect(cmd):
            calls.append(cmd)
            if cmd in {"dir flash:", "display directory flash:"}:
                raise Exception("not supported")
            if cmd == "rollback configuration to file backup-before-replace.cfg":
                return "Configuration is saved."
            if cmd == "save force":
                return "Configuration is saved."
            raise Exception("not found")

        device.send_command = MagicMock(side_effect=rollback_side_effect)
        device.rollback()

        assert calls[2] == "rollback configuration to file backup-before-replace.cfg"
        assert "rollback configuration to file backup-before-merge.cfg" not in calls

    def test_rollback_prefers_newest_backup_from_directory_listing(self, device):
        device.device = MagicMock()
        calls = []

        def side_effect(cmd):
            calls.append(cmd)
            if cmd == "dir flash:":
                return (
                    "Directory of flash:/\n"
                    "  14   -rw-         9400  Oct 01 2023 14:54:32   backup-before-merge.cfg\n"
                    "  15   -rw-         9400  Oct 01 2023 14:55:32   backup-before-replace.cfg\n"
                )
            if cmd == "rollback configuration to file backup-before-replace.cfg":
                return "Configuration is saved."
            if cmd == "save force":
                return "Configuration is saved."
            raise Exception("not found")

        device.send_command = MagicMock(side_effect=side_effect)
        device.rollback()

        assert calls[:2] == ["dir flash:", "rollback configuration to file backup-before-replace.cfg"]
        assert "rollback configuration to file backup-before-merge.cfg" not in calls

    def test_rollback_falls_back_to_legacy_replace_command(self, device):
        device.device = MagicMock()
        calls = []

        def side_effect(cmd):
            calls.append(cmd)
            if cmd == "configuration replace file flash:/backup-before-merge.cfg":
                return "Configuration is saved."
            if cmd == "save force":
                return "Configuration is saved."
            raise Exception("not found")

        device.send_command = MagicMock(side_effect=side_effect)
        device.rollback()

        assert calls[:4] == [
            "dir flash:",
            "display directory flash:",
            "rollback configuration to file backup-before-merge.cfg",
            "configuration replace file flash:/backup-before-merge.cfg",
        ]
        assert calls[-1] == "save force"

    def test_rollback_treats_cli_error_text_as_failure(self, device):
        device.device = MagicMock()
        calls = []

        def side_effect(cmd):
            calls.append(cmd)
            if cmd == "rollback configuration to file backup-before-merge.cfg":
                return "Error: File does not exist."
            if cmd == "configuration replace file flash:/backup-before-merge.cfg":
                return "Configuration is saved."
            if cmd == "save force":
                return "Configuration is saved."
            raise Exception("not found")

        device.send_command = MagicMock(side_effect=side_effect)
        device.rollback()

        assert calls[:4] == [
            "dir flash:",
            "display directory flash:",
            "rollback configuration to file backup-before-merge.cfg",
            "configuration replace file flash:/backup-before-merge.cfg",
        ]

    def test_rollback_fails_when_no_backup(self, device):
        device.device = MagicMock()
        device.send_command = MagicMock(side_effect=Exception("not found"))
        with pytest.raises(Exception, match="no backup config found"):
            device.rollback()


class TestRunningConfigParsers:
    def test_get_ntp_servers_and_peers(self, device):
        device.send_command = MagicMock(
            return_value=(
                "sysname core-sw\n"
                "ntp-service unicast-server 192.0.2.10\n"
                "ntp-service server pool.ntp.org\n"
                "ntp-service peer 192.0.2.20\n"
            )
        )

        assert device.get_ntp_servers() == {"192.0.2.10": {}, "pool.ntp.org": {}}
        assert device.get_ntp_peers() == {"192.0.2.20": {}}

    def test_get_snmp_information(self, device):
        device.send_command = MagicMock(
            return_value=(
                "snmp-agent community read simple public acl 2001\n"
                "snmp-agent community write cipher private\n"
                "snmp-agent sys-info contact NOC Team\n"
                "snmp-agent sys-info location DC1 RowA\n"
            )
        )
        device.get_facts = MagicMock(return_value={"serial_number": "SN123456"})

        result = device.get_snmp_information()

        assert result == {
            "chassis_id": "SN123456",
            "community": {
                "public": {"mode": "ro", "acl": "2001"},
                "private": {"mode": "rw", "acl": ""},
            },
            "contact": "NOC Team",
            "location": "DC1 RowA",
        }

    def test_get_network_instances(self, device):
        device.send_command = MagicMock(
            return_value=(
                "ip vpn-instance BLUE\n"
                " route-distinguisher 65000:100\n"
                "#\n"
                "interface Vlan-interface100\n"
                " ip binding vpn-instance BLUE\n"
                "#\n"
                "interface LoopBack0\n"
                "#\n"
            )
        )

        result = device.get_network_instances()

        assert result["BLUE"]["state"]["route_distinguisher"] == "65000:100"
        assert "VLAN100" in result["BLUE"]["interfaces"]["interface"]
        assert "LoopBack0" in result["default"]["interfaces"]["interface"]

    def test_get_users(self, device):
        device.send_command = MagicMock(
            return_value=(
                "local-user admin class manage\n"
                " password cipher $c$3$admin-secret\n"
                " authorization-attribute user-role network-admin\n"
                "#\n"
                "local-user ops class monitor\n"
                " password irreversible-cipher $c$3$ops-secret\n"
                " authorization-attribute user-role network-operator\n"
                "#\n"
                "local-user guest class visit\n"
                " password simple guest\n"
                "#\n"
            )
        )

        assert device.get_users() == {
            "admin": {"level": 15, "password": "$c$3$admin-secret", "sshkeys": []},
            "ops": {"level": 5, "password": "$c$3$ops-secret", "sshkeys": []},
            "guest": {"level": 1, "password": "guest", "sshkeys": []},
        }

    def test_get_ntp_stats_from_sessions(self, device):
        device.send_command = MagicMock(
            side_effect=[
                (
                    "       address         refid      st t when poll reach   delay   offset  disp\n"
                    " =============================================================================\n"
                    "* 192.168.1.1    192.168.0.1     2  u   8   64  377   2.545   0.034   0.123\n"
                    "+ 192.168.2.2    192.168.0.2     2  u   9   64  377   2.499   0.056   0.134\n"
                )
            ]
        )

        result = device.get_ntp_stats()

        assert result == [
            {
                "remote": "192.168.1.1",
                "referenceid": "192.168.0.1",
                "synchronized": True,
                "stratum": 2,
                "type": "u",
                "when": "8",
                "hostpoll": 64,
                "reachability": 377,
                "delay": 2.545,
                "offset": 0.034,
                "jitter": 0.123,
            },
            {
                "remote": "192.168.2.2",
                "referenceid": "192.168.0.2",
                "synchronized": False,
                "stratum": 2,
                "type": "u",
                "when": "9",
                "hostpoll": 64,
                "reachability": 377,
                "delay": 2.499,
                "offset": 0.056,
                "jitter": 0.134,
            },
        ]

    def test_get_ntp_stats_falls_back_to_status(self, device):
        device.send_command = MagicMock(
            side_effect=[
                "",
                "Clock status: synchronized\nClock stratum: 3\nReference clock ID: 10.10.1.1\n",
            ]
        )

        assert device.get_ntp_stats() == [
            {
                "remote": "10.10.1.1",
                "referenceid": "10.10.1.1",
                "synchronized": True,
                "stratum": 3,
                "type": "-",
                "when": "",
                "hostpoll": 0,
                "reachability": 0,
                "delay": 0.0,
                "offset": 0.0,
                "jitter": 0.0,
            }
        ]


class TestOperationalParsers:
    def test_cli_rejects_non_list_input(self, device):
        with pytest.raises(TypeError, match="list of strings"):
            device.cli("display version")  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="only strings"):
            device.cli(["display version", 123])  # type: ignore[list-item]

    def test_ping_success(self, device):
        device.send_command = MagicMock(
            return_value=(
                "PING 192.168.1.1: 56 data bytes, press CTRL_C to break\n"
                "Reply from 192.168.1.1: bytes=56 Sequence=1 ttl=64 time=2.5 ms\n"
                "Reply from 192.168.1.1: bytes=56 Sequence=2 ttl=64 time=3 ms\n"
                "Reply from 192.168.1.1: bytes=56 Sequence=3 ttl=64 time<1 ms\n"
                "5 packet(s) transmitted\n"
                "5 packet(s) received\n"
                "round-trip min/avg/max = 1/2/3 ms\n"
            )
        )

        result = device.ping("192.168.1.1")

        assert result["success"]["probes_sent"] == 5
        assert result["success"]["packet_loss"] == 0
        assert result["success"]["rtt_avg"] == 2.0
        assert result["success"]["results"] == [
            {"ip_address": "192.168.1.1", "rtt": 2.5},
            {"ip_address": "192.168.1.1", "rtt": 3.0},
            {"ip_address": "192.168.1.1", "rtt": 1.0},
        ]

    def test_ping_error(self, device):
        device.send_command = MagicMock(return_value="Error: Failed to resolve host")

        assert device.ping("bad-host") == {"error": "Error: Failed to resolve host"}

    def test_ping_rejects_command_injection_input(self, device):
        with pytest.raises(ValueError, match="Invalid ping destination"):
            device.ping("192.0.2.1\ndisplay current-configuration")

    def test_ping_rejects_invalid_numeric_arguments(self, device):
        with pytest.raises(ValueError, match="Invalid ping ttl"):
            device.ping("192.0.2.1", ttl="1\ndisplay current-configuration")  # type: ignore[arg-type]

    def test_traceroute_success(self, device):
        device.send_command = MagicMock(
            return_value=(
                "traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 40 byte packets\n"
                " 1  10.0.0.1         1 ms  1 ms  2 ms\n"
                " 2  10.0.0.1  3 ms  10.0.0.2  4 ms  10.0.0.3  5 ms\n"
                " 3  * * *\n"
                " 4  core-gw 172.16.0.1  20 ms  21 ms  22 ms\n"
                " 5  8.8.8.8          30 ms  31 ms  32 ms\n"
            )
        )

        result = device.traceroute("8.8.8.8")

        assert result["success"][1]["probes"][1]["ip_address"] == "10.0.0.1"
        assert result["success"][2]["probes"][2]["ip_address"] == "10.0.0.2"
        assert result["success"][2]["probes"][3]["ip_address"] == "10.0.0.3"
        assert result["success"][3]["probes"][1] == {"host_name": "*", "ip_address": "*", "rtt": -1.0}
        assert result["success"][4]["probes"][1]["host_name"] == "core-gw"
        assert result["success"][5]["probes"][3]["rtt"] == 32.0

    def test_traceroute_rejects_invalid_source(self, device):
        with pytest.raises(ValueError, match="Invalid traceroute source"):
            device.traceroute("8.8.8.8", source="192.0.2.1\tfoo")

    def test_traceroute_rejects_invalid_numeric_arguments(self, device):
        with pytest.raises(ValueError, match="Invalid traceroute timeout"):
            device.traceroute("8.8.8.8", timeout="2\ndisplay version")  # type: ignore[arg-type]

    def test_get_mac_address_table_uses_normalized_move_keys(self, device):
        device._get_structured_output.side_effect = [
            [{"mac_address": "0012-3456-789a", "vlan": "10", "state": "dynamic", "interface": "GigabitEthernet1/0/1"}],
            [
                {
                    "mac_address": "0012-3456-789a",
                    "vlan": "10",
                    "current_port": "GigabitEthernet1/0/1",
                    "source_port": "GigabitEthernet1/0/2",
                    "last_move": "2024-01-02 03:04:05",
                    "times": "7",
                }
            ],
        ]

        result = device.get_mac_address_table()

        assert result == [
            {
                "mac": "00:12:34:56:78:9A",
                "interface": "GigabitEthernet1/0/1",
                "vlan": 10,
                "static": False,
                "active": True,
                "last_move": strptime("2024-01-02 03:04:05"),
                "moves": 7,
            }
        ]

    def test_get_bgp_neighbors(self, device):
        device.send_command = MagicMock(
            side_effect=[
                (
                    "BGP local router ID : 10.1.1.1\n"
                    "Local AS number : 65001\n"
                    "Total number of peers : 2                 Peers in Established state : 1\n"
                    "Peer        Remote-AS MsgRcvd MsgSent  TblVer  InQ  OutQ Up/Down       State/PfxRcd\n"
                    "2.2.2.2     65002     12345   12344    32      0    0    00:35:27      Established/10\n"
                    "3.3.3.3     65003     0       0        0       0    0    00:00:12      Idle(Admin)\n"
                ),
                (
                    "BGP peer is 2.2.2.2, remote AS 65002\n"
                    " BGP version 4, remote router ID 2.2.2.22\n"
                    ' Peer\'s description: "upstream-a"\n'
                    " Advertised total routes: 7\n"
                ),
                "BGP version 4, remote router ID 3.3.3.33\n",
            ]
        )

        result = device.get_bgp_neighbors()

        assert result["global"]["router_id"] == "10.1.1.1"
        assert result["global"]["peers"]["2.2.2.2"] == {
            "local_as": 65001,
            "remote_as": 65002,
            "remote_id": "2.2.2.22",
            "is_up": True,
            "is_enabled": True,
            "description": "upstream-a",
            "uptime": 2127,
            "address_family": {
                "ipv4 unicast": {
                    "received_prefixes": 10,
                    "accepted_prefixes": 10,
                    "sent_prefixes": 7,
                }
            },
        }
        assert result["global"]["peers"]["3.3.3.3"]["is_enabled"] is False
        assert result["global"]["peers"]["3.3.3.3"]["address_family"]["ipv4 unicast"]["received_prefixes"] == 0

    def test_get_route_to_from_table_output(self, device):
        device.send_command = MagicMock(
            return_value=(
                "Routing Table : _public_\n"
                "Destination/Mask Proto Pre Cost Flags NextHop Interface Age\n"
                "10.1.2.0/24 OSPF 10 20 D 10.1.1.3 GigabitEthernet1/0/2 1d2h\n"
                "10.1.2.0/24 Static 60 0 RD 10.1.1.4 GigabitEthernet1/0/3 2h23m\n"
            )
        )

        result = device.get_route_to("10.1.2.0/24")

        assert result["10.1.2.0/24"][0] == {
            "protocol": "OSPF",
            "current_active": True,
            "last_active": False,
            "age": 93600,
            "next_hop": "10.1.1.3",
            "outgoing_interface": "GigabitEthernet1/0/2",
            "selected_next_hop": True,
            "preference": 10,
            "inactive_reason": "",
            "routing_table": "global",
            "protocol_attributes": {"metric": 20},
        }
        assert result["10.1.2.0/24"][1]["protocol"] == "STATIC"
        assert result["10.1.2.0/24"][1]["selected_next_hop"] is False

    def test_get_route_to_protocol_filter_and_verbose_fallback(self, device):
        device.send_command = MagicMock(
            return_value=(
                "Routing Tables : Public\n"
                "\n"
                "Destination: 10.10.10.0/24\n"
                "Protocol : BGP        Preference : 255         Cost : 0\n"
                "NextHop  : 2.2.2.2    Interface: GigabitEthernet1/0/1\n"
                "Age      : 01:34:12\n"
            )
        )

        result = device.get_route_to("10.10.10.0/24", protocol="bgp")

        assert result == {
            "10.10.10.0/24": [
                {
                    "protocol": "BGP",
                    "current_active": True,
                    "last_active": False,
                    "age": 5652,
                    "next_hop": "2.2.2.2",
                    "outgoing_interface": "GigabitEthernet1/0/1",
                    "selected_next_hop": True,
                    "preference": 255,
                    "inactive_reason": "",
                    "routing_table": "global",
                    "protocol_attributes": {"metric": 0},
                }
            ]
        }

    def test_get_route_to_rejects_unsupported_modes(self, device):
        with pytest.raises(NotImplementedError, match="longer route lookup"):
            device.get_route_to("10.1.2.0/24", longer=True)

        with pytest.raises(NotImplementedError, match="IPv6 route lookup"):
            device.get_route_to("2001:db8::/64")

    def test_get_route_to_rejects_invalid_destination(self, device):
        with pytest.raises(ValueError, match="Invalid route destination"):
            device.get_route_to("10.1.2.0/24\nscreen-length disable")

    def test_get_interfaces_counters(self, device):
        device.send_command = MagicMock(
            return_value=(
                "GigabitEthernet1/0/1 current state: UP\n"
                "Line protocol state: UP\n"
                "Input: 100 packets, 1000 bytes\n"
                "  Unicast: 80\n"
                "  Multicast: 15\n"
                "  Broadcast: 5\n"
                "  Total Error: 2\n"
                "  Discard: 1\n"
                "Output: 120 packets, 1500 bytes\n"
                "  90 unicast\n"
                "  20 multicast\n"
                "  10 broadcast\n"
                "  3 errors\n"
                "  4 discard\n"
            )
        )

        result = device.get_interfaces_counters()

        assert result["GigabitEthernet1/0/1"] == {
            "tx_errors": 3,
            "rx_errors": 2,
            "tx_discards": 4,
            "rx_discards": 1,
            "tx_octets": 1500,
            "rx_octets": 1000,
            "tx_unicast_packets": 90,
            "rx_unicast_packets": 80,
            "tx_multicast_packets": 20,
            "rx_multicast_packets": 15,
            "tx_broadcast_packets": 10,
            "rx_broadcast_packets": 5,
        }

    def test_get_ipv6_neighbors_table(self, device):
        device.send_command = MagicMock(
            return_value=(
                "IPv6 Address                   MAC Address        VLAN/Status      Interface\n"
                "2001:db8::1                    0012-3456-789a     Reach            Vlan-interface1\n"
                "fe80::201:2345:6789:abcd       0022-3344-5566     120 Stale        GigabitEthernet1/0/1\n"
            )
        )

        result = device.get_ipv6_neighbors_table()

        assert result == [
            {
                "interface": "VLAN1",
                "mac": "00:12:34:56:78:9A",
                "ip": "2001:db8::1",
                "age": -1.0,
                "state": "Reach",
            },
            {
                "interface": "GigabitEthernet1/0/1",
                "mac": "00:22:33:44:55:66",
                "ip": "fe80::201:2345:6789:abcd",
                "age": 120.0,
                "state": "Stale",
            },
        ]

    def test_send_command_serializes_device_access(self, device):
        device.device = MagicMock()
        active_calls = 0
        max_concurrent_calls = 0
        state_lock = threading.Lock()

        def fake_send_command(command, *args, **kwargs):
            nonlocal active_calls, max_concurrent_calls
            with state_lock:
                active_calls += 1
                max_concurrent_calls = max(max_concurrent_calls, active_calls)
            time.sleep(0.02)
            with state_lock:
                active_calls -= 1
            return command

        device.device.send_command.side_effect = fake_send_command

        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(device.send_command, [f"cmd-{idx}" for idx in range(4)]))

        assert results == ["cmd-0", "cmd-1", "cmd-2", "cmd-3"]
        assert max_concurrent_calls == 1

    def test_other_device_io_uses_same_lock(self, device):
        device.device = MagicMock()
        active_calls = 0
        max_concurrent_calls = 0
        state_lock = threading.Lock()

        def track_call(result):
            nonlocal active_calls, max_concurrent_calls
            with state_lock:
                active_calls += 1
                max_concurrent_calls = max(max_concurrent_calls, active_calls)
            time.sleep(0.02)
            with state_lock:
                active_calls -= 1
            return result

        device.device.find_prompt.side_effect = lambda: track_call("<sysname>")
        device.device.send_config_set.side_effect = lambda commands: track_call("\n".join(commands))

        with ThreadPoolExecutor(max_workers=2) as executor:
            prompt_future = executor.submit(device.find_prompt)
            config_future = executor.submit(device.send_config_set, ["sysname test-sw"])

        assert prompt_future.result() == "<sysname>"
        assert config_future.result() == "sysname test-sw"
        assert max_concurrent_calls == 1
