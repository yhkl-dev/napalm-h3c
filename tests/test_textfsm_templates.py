"""TextFSM template tests against realistic H3C Comware device output."""

import os

import pytest
from textfsm import TextFSM  # type: ignore[import-untyped]

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "../napalm_h3c_comware/utils/textfsm_templates")


def _load_template(name: str) -> TextFSM:
    with open(os.path.join(TEMPLATE_DIR, f"{name}.tpl")) as f:
        return TextFSM(f)


# ── display_version ──────────────────────────────────────────────────────────


@pytest.fixture
def version_template() -> TextFSM:
    return _load_template("display_version")


def test_version_parsing(version_template: TextFSM) -> None:
    output = """
H3C Comware Software, Version 7.1.070, Release 6607
Copyright (c) 2004-2020 New H3C Technologies Co., Ltd. All rights reserved.
H3C S6850-2C uptime is 69 weeks, 6 days, 23 hours, 24 minutes
"""
    result = version_template.ParseText(output)
    assert result == [["Release 6607", "H3C", "S6850-2C", "69 weeks, 6 days, 23 hours, 24 minutes"]]


def test_version_single_device(version_template: TextFSM) -> None:
    output = """
H3C Comware Software, Version 7.1.064, Release 6318P01
H3C S5130S-52S-HI uptime is 1 week, 2 days, 3 hours, 45 minutes
"""
    result = version_template.ParseText(output)
    assert result[0][2] == "S5130S-52S-HI"
    assert result[0][0] == "Release 6318P01"


# ── display_interface ───────────────────────────────────────────────────────


@pytest.fixture
def interface_template() -> TextFSM:
    return _load_template("display_interface")


def test_interface_parsing(interface_template: TextFSM) -> None:
    output = """
GigabitEthernet1/0/1
Current state: UP
Line protocol state: UP
IP packet frame type:PKTFMT_ETHNT_2, hardware address: 0012-3456-789a
Description: Uplink to Core
Bandwidth: 1000000 kbps
Maximum transmission unit: 1500
Media type is twisted pair, port hardware type is 1000_BASE_T
1000M-speed mode, full-duplex mode
Internet address: 10.1.1.1/24 Primary
PVID: 100
Port link-type: trunk
Last link flapping: 12 days 5 hours 30 minutes

GigabitEthernet1/0/2
Current state: Administratively DOWN
Line protocol state: DOWN
IP packet frame type:PKTFMT_ETHNT_2, hardware address: 0012-3456-789b
Description: not configured
Bandwidth: 1000000 kbps
Maximum transmission unit: 1500
Media type is twisted pair, port hardware type is 1000_BASE_T
auto-speed mode, full-duplex mode
PVID: 1
Port link-type: access
Last link flapping: Never
"""
    result = interface_template.ParseText(output)

    assert len(result) == 2

    assert result[0][0] == "GigabitEthernet1/0/1"
    assert result[0][1] == "UP"
    assert result[0][2] == "UP"
    assert result[0][3] == "0012-3456-789a"
    assert result[0][4] == "Uplink to Core"
    assert result[0][5] == "1000000"
    assert result[0][6] == "1500"
    assert result[0][13] == "12 days 5 hours 30 minutes"

    assert result[1][0] == "GigabitEthernet1/0/2"
    assert "Administratively" in result[1][1]
    assert result[1][2] == "DOWN"


# ── display_arp ─────────────────────────────────────────────────────────────


@pytest.fixture
def arp_template() -> TextFSM:
    return _load_template("display_arp")


def test_arp_parsing(arp_template: TextFSM) -> None:
    output = """IP address       MAC address    VLAN    Interface         Aging   Type
10.1.1.1         0012-3456-789a 100     XGE1/0/1         1200    Dynamic
10.1.1.254       0022-3344-5566 N/A     MGE1/0/2         60      Static
192.168.1.1      00aa-bbcc-ddee 200     BAGG1            300     Dynamic
"""
    result = arp_template.ParseText(output)

    assert len(result) == 3
    assert result[0] == ["10.1.1.1", "0012-3456-789a", "100", "XGE1/0/1", "1200", "Dynamic"]
    assert result[1] == ["10.1.1.254", "0022-3344-5566", "N/A", "MGE1/0/2", "60", "Static"]


# ── display_vlan_all ────────────────────────────────────────────────────────


@pytest.fixture
def vlan_template() -> TextFSM:
    return _load_template("display_vlan_all")


def test_vlan_parsing(vlan_template: TextFSM) -> None:
    output = """
 VLAN ID: 1
   VLAN type: Static
   Route interface: Not configured
   Description: VLAN 0001
   Name: VLAN 0001
       GigabitEthernet1/0/1  GigabitEthernet1/0/2  GigabitEthernet1/0/5

 VLAN ID: 100
   VLAN type: Static
   Route interface: Not configured
   Description: Mgmt-VLAN
   Name: Mgmt
       GigabitEthernet1/0/10  GigabitEthernet1/0/11
"""
    result = vlan_template.ParseText(output)

    assert len(result) == 2
    assert result[0][0] == "1"
    assert "VLAN 0001" in result[0][2]
    assert "GigabitEthernet1/0/1" in result[0][4]
    assert "GigabitEthernet1/0/2" in result[0][4]

    assert result[1][0] == "100"
    assert "Mgmt" in result[1][2]


# ── display_environment ─────────────────────────────────────────────────────


@pytest.fixture
def environment_template() -> TextFSM:
    return _load_template("display_environment")


def test_environment_chassis_device(environment_template: TextFSM) -> None:
    output = """
Chassis
 Chassis 1
 1 1 inflow 1    25      -5     27     30
 1 1 outflow 1   22      -5     27     30
 1 2 inflow 1    30      -5     32     35
"""
    result = environment_template.ParseText(output)

    assert len(result) == 3
    assert result[0] == ["1", "1", "inflow 1", "25", "27", "30"]
    assert result[2][3] == "30"


def test_environment_normal_device(environment_template: TextFSM) -> None:
    output = """
Slot
 1 inflow 1              28      -5     30     35
 1 outflow 1             25      -5     30     35
"""
    result = environment_template.ParseText(output)

    assert len(result) == 2
    assert result[0][1] == "1"
    assert result[0][3] == "28"


# ── display_ip_interface ────────────────────────────────────────────────────


@pytest.fixture
def ip_interface_template() -> TextFSM:
    return _load_template("display_ip_interface")


def test_ip_interface_parsing(ip_interface_template: TextFSM) -> None:
    output = """
LoopBack0 current state: UP
Internet Address is 10.255.255.1/32 Primary
GigabitEthernet1/0/1 current state: UP
Internet Address is 192.168.1.1/24 Primary
Internet Address is 10.0.0.1/30 Sub
Vlan-interface100 current state: UP
Internet Address is 172.16.0.1/24 Primary
"""
    result = ip_interface_template.ParseText(output)

    assert len(result) == 3
    assert result[0][0] == "LoopBack0"
    assert "10.255.255.1/32" in result[0][1]
    assert result[1][0] == "GigabitEthernet1/0/1"
    assert len(result[1][1]) == 2


# ── display_power ───────────────────────────────────────────────────────────


@pytest.fixture
def power_template() -> TextFSM:
    return _load_template("display_power")


def test_power_normal_device(power_template: TextFSM) -> None:
    output = """
 Slot 1
 1  Normal  AC   5.2  12.0  62.4
 2  Absent  --   0.0  0.0   0.0
"""
    result = power_template.ParseText(output)

    assert len(result) == 2
    assert result[0][3] == "Normal"
    assert result[1][3] == "Absent"


# ── display_fan ─────────────────────────────────────────────────────────────


@pytest.fixture
def fan_template() -> TextFSM:
    return _load_template("display_fan")


def test_fan_normal_device(fan_template: TextFSM) -> None:
    output = """
 Slot 1
 Fan 1
 State : Normal
 Fan 2
 State : Normal
 Fan 3
 State : Normal
 Fan 4
 State : Normal
"""
    result = fan_template.ParseText(output)

    assert len(result) == 4
    assert result[0][3] == "Normal"
    assert result[1][3] == "Normal"


# ── display_cpu-usage_summary ───────────────────────────────────────────────


@pytest.fixture
def cpu_template() -> TextFSM:
    return _load_template("display_cpu-usage_summary")


def test_cpu_single_device(cpu_template: TextFSM) -> None:
    output = """
CPU usage ratio: 23%
CPU    5 sec   1 min   5 min
0      23%     22%     24%
"""
    result = cpu_template.ParseText(output)

    assert len(result) == 1
    # Fields: CHASSIS, SLOT, CPU_ID, FIVE_SEC, ONE_MIN, FIVE_MIN
    assert result[0][2] == "0"
    assert result[0][3] == "23"
    assert result[0][4] == "22"
    assert result[0][5] == "24"


def test_cpu_normal_device(cpu_template: TextFSM) -> None:
    output = """
Slot 1 CPU usage:
Slot     CPU     5 sec   1 min   5 min
1        0       15%     14%     16%
1        1       10%     11%     9%
"""
    result = cpu_template.ParseText(output)

    assert len(result) == 2
    # Fields: CHASSIS, SLOT, CPU_ID, FIVE_SEC, ONE_MIN, FIVE_MIN
    assert result[0] == ["", "1", "0", "15", "14", "16"]
    assert result[1] == ["", "1", "1", "10", "11", "9"]


def test_cpu_chassis_device(cpu_template: TextFSM) -> None:
    output = """
Chassis 1 Slot 1 CPU usage:
Chassis Slot    CPU     5 sec   1 min   5 min
1       1       0       23%     22%     24%
1       1       1       18%     19%     17%
"""
    result = cpu_template.ParseText(output)

    assert len(result) == 2
    assert result[0] == ["1", "1", "0", "23", "22", "24"]


# ── display_device_manuinfo ──────────────────────────────────────────────────


@pytest.fixture
def manuinfo_template() -> TextFSM:
    return _load_template("display_device_manuinfo")


def test_manuinfo_parsing(manuinfo_template: TextFSM) -> None:
    output = """
 Chassis 1
 Slot 1
 DEVICE_NAME          : S6850-2C
 DEVICE_SERIAL_NUMBER : 210235A1ELH123000456
 MAC_ADDRESS          : 0012-3456-789a
 MANUFACTURING_DATE   : 2020-05-15
 VENDOR_NAME          : H3C

 Slot 2
 DEVICE_NAME          : S6850-2C
 DEVICE_SERIAL_NUMBER : 210235A1ELH123000457
 MAC_ADDRESS          : 0012-3456-789b
 MANUFACTURING_DATE   : 2020-05-15
 VENDOR_NAME          : H3C
"""
    result = manuinfo_template.ParseText(output)

    assert len(result) >= 2
    assert result[0][0] == "1"
    assert result[0][1] == "Slot"
    assert result[0][2] == "1"
    assert result[0][3] == "S6850-2C"
    assert result[0][4] == "210235A1ELH123000456"


def test_manuinfo_power_not_supported(manuinfo_template: TextFSM) -> None:
    output = """
 Chassis 1
 Power 1
 The operation is not supported on the slot.
"""
    result = manuinfo_template.ParseText(output)
    assert len(result) == 1
    assert result[0][1] == "Power"
    assert result[0][2] == "1"
