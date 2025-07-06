import pytest
from textfsm import TextFSM


@pytest.fixture
def lldp_template():
    with open("napalm_h3c_comware/utils/textfsm_templates/display_lldp_neighbor-information_verbose.tpl") as f:
        return TextFSM(f)


@pytest.fixture
def empty_output():
    return """
The LLDP service is not running
    """


@pytest.fixture
def normal_output():
    return """
LLDP neighbor-information of port 50[Ten-GigabitEthernet1/0/50]:
LLDP agent nearest-bridge:
 LLDP neighbor index : 1
 Update time         : 69 days, 23 hours, 24 minutes, 8 seconds
 Chassis type        : MAC address
 Chassis ID          : 00be-d50f-3b60
 Port ID type        : Interface name
 Port ID             : Ten-GigabitEthernet2/1/15
 Time to live        : 121
 Port description    : to IDC-security-SW140
 System name         : NPSHD-CS-6680-JF-254
 System description  :
   H3C Comware Platform Software, Software Version 7.1.070, Release 6607
   H3C S6850-2C
   Copyright (c) 2004-2020 New H3C Technologies Co., Ltd. All rights reserved.
 System capabilities supported : Bridge, Router, Customer Bridge, Service Bridge
 System capabilities enabled   : Bridge, Router, Customer Bridge
 Management address type           : All802
 Management address                : 00be-d50f-3aec
 Management address interface type : IfIndex
 Management address interface ID   : Unknown
 Management address OID            : 0
 Port VLAN ID(PVID)  : 1
 Link aggregation supported : Yes
 Link aggregation enabled   : Yes
 Aggregation port ID        : 2181
 Auto-negotiation supported : Yes
 Auto-negotiation enabled   : Yes
 OperMau                    : Speed(10000)/Duplex(Full)
 Power port class           : PD
 PSE power supported        : No
 PSE power enabled          : No
 PSE pairs control ability  : No
 Power pairs                : Signal
 Port power classification  : Class 0
 Maximum frame size         : 9416

LLDP neighbor-information of port 51[Ten-GigabitEthernet1/0/51]:
LLDP agent nearest-bridge:
 LLDP neighbor index : 1
 Update time         : 85 days, 21 hours, 33 minutes, 10 seconds
 Chassis type        : MAC address
 Chassis ID          : 305f-7733-5958
 Port ID type        : Interface name
 Port ID             : Ten-GigabitEthernet2/0/52
 Time to live        : 121
 Port description    : Ten-GigabitEthernet2/0/52 Interface
 System name         : NPSHD-ES-5130-JF-172.31.19.250
 System description  :
   H3C Comware Platform Software, Software Version 7.1.070, Release 6318P01
   H3C S5130S-52S-HI
   Copyright (c) 2004-2020 New H3C Technologies Co., Ltd. All rights reserved.
 System capabilities supported : Bridge, Router, Customer Bridge, Service Bridge
 System capabilities enabled   : Bridge, Router, Customer Bridge

LLDP neighbor-information of port 52[Ten-GigabitEthernet1/0/52]:
LLDP agent nearest-bridge:
 LLDP neighbor index : 1
 Update time         : 85 days, 21 hours, 33 minutes, 10 seconds
 Chassis type        : MAC address
 Chassis ID          : 305f-7733-5958
 Port ID type        : Interface name
 Port ID             : Ten-GigabitEthernet2/0/51
 Time to live        : 121
 Port description    : Ten-GigabitEthernet2/0/51 Interface
 System name         : NPSHD-ES-5130-JF-172.31.19.250
 System description  :
   H3C Comware Platform Software, Software Version 7.1.070, Release 6318P01
   H3C S5130S-52S-HI
   Copyright (c) 2004-2020 New H3C Technologies Co., Ltd. All rights reserved.
 System capabilities supported : Bridge, Router, Customer Bridge, Service Bridge
 System capabilities enabled   : Bridge, Router, Customer Bridge

LLDP neighbor-information of port 113[Ten-GigabitEthernet2/0/50]:
LLDP agent nearest-bridge:
 LLDP neighbor index : 1
 Update time         : 69 days, 23 hours, 24 minutes, 8 seconds
 Chassis type        : MAC address
 Chassis ID          : 00be-d50f-3b60
 Port ID type        : Interface name
 Port ID             : Ten-GigabitEthernet1/1/15
 Time to live        : 121
 Port description    : to IDC-security-SW140
 System name         : NPSHD-CS-6680-JF-254
 System description  :
   H3C Comware Platform Software, Software Version 7.1.070, Release 6607
   H3C S6850-2C
   Copyright (c) 2004-2020 New H3C Technologies Co., Ltd. All rights reserved.
 System capabilities supported : Bridge, Router, Customer Bridge, Service Bridge
 System capabilities enabled   : Bridge, Router, Customer Bridge
 Management address type           : IPv4
 Management address                : 134.119.9.254
 Management address interface type : IfIndex
 Management address interface ID   : 2154
 Management address OID            : 0
 Port VLAN ID(PVID)  : 1
 Link aggregation supported : Yes
 Link aggregation enabled   : Yes
 Aggregation port ID        : 2181
 Auto-negotiation supported : Yes
 Auto-negotiation enabled   : Yes
 OperMau                    : Speed(10000)/Duplex(Full)
 Power port class           : PD
 PSE power supported        : No
 PSE power enabled          : No
 PSE pairs control ability  : No
 Power pairs                : Signal
 Port power classification  : Class 0
 Maximum frame size         : 9416

LLDP neighbor-information of port 114[Ten-GigabitEthernet2/0/51]:
LLDP agent nearest-bridge:
 LLDP neighbor index : 1
 Update time         : 85 days, 21 hours, 33 minutes, 10 seconds
 Chassis type        : MAC address
 Chassis ID          : 305f-7733-5958
 Port ID type        : Interface name
 Port ID             : Ten-GigabitEthernet1/0/52
 Time to live        : 121
 Port description    : Ten-GigabitEthernet1/0/52 Interface
 System name         : NPSHD-ES-5130-JF-172.31.19.250
 System description  :
   H3C Comware Platform Software, Software Version 7.1.070, Release 6318P01
   H3C S5130S-52S-HI
   Copyright (c) 2004-2020 New H3C Technologies Co., Ltd. All rights reserved.
 System capabilities supported : Bridge, Router, Customer Bridge, Service Bridge
 System capabilities enabled   : Bridge, Router, Customer Bridge

LLDP neighbor-information of port 115[Ten-GigabitEthernet2/0/52]:
LLDP agent nearest-bridge:
 LLDP neighbor index : 1
 Update time         : 85 days, 21 hours, 33 minutes, 10 seconds
 Chassis type        : MAC address
 Chassis ID          : 305f-7733-5958
 Port ID type        : Interface name
 Port ID             : Ten-GigabitEthernet1/0/51
 Time to live        : 121
 Port description    : Ten-GigabitEthernet1/0/51 Interface
 System name         : NPSHD-ES-5130-JF-172.31.19.250
 System description  :
   H3C Comware Platform Software, Software Version 7.1.070, Release 6318P01
   H3C S5130S-52S-HI
   Copyright (c) 2004-2020 New H3C Technologies Co., Ltd. All rights reserved.
 System capabilities supported : Bridge, Router, Customer Bridge, Service Bridge
 System capabilities enabled   : Bridge, Router, Customer Bridge
    """


def test_empty_output(lldp_template, empty_output):
    result = lldp_template.ParseText(empty_output)
    assert len(result) == 0


def test_normal_parsing(lldp_template, normal_output):
    result = lldp_template.ParseText(normal_output)

    assert len(result) == 6

    record = result[0]
    assert record[0] == "Ten-GigabitEthernet1/0/50"
    assert record[1] == "1"
    assert "NPSHD-CS-6680-JF-254" in record[6]
    assert "to IDC-security-SW140" in record[5]

    assert "Software Version 7.1.070" in record[7][0]
