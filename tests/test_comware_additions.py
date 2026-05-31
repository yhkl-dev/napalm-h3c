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

        with pytest.raises(Exception, match="only supported for replace candidates"):
            device.compare_config()

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
        device.send_command.assert_called_once_with("save force")
        assert device.get_config(retrieve="candidate")["candidate"] == ""

    def test_commit_config_rejects_replace_candidate(self, device):
        device.load_replace_candidate(config="sysname replacement-sw\n")

        with pytest.raises(Exception, match="Replace commit is not supported"):
            device.commit_config()

    def test_commit_config_rejects_commit_message_and_revert_timer(self, device):
        with pytest.raises(NotImplementedError, match="commit messages"):
            device.commit_config(message="change-ticket")

        with pytest.raises(NotImplementedError, match="revert timers"):
            device.commit_config(revert_in=300)


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
