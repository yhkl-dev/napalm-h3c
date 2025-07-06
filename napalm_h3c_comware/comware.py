import logging
from collections import defaultdict
from operator import itemgetter
from typing import (
    Any,
    Dict,
    List,
    Literal,
    NewType,
    Optional,
    TypeAlias,
    TypedDict,
    Union,
)

from napalm.base import models
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import CommandErrorException
from napalm.base.helpers import (
    mac,
    textfsm_extractor,
)
from napalm.base.netmiko_helpers import netmiko_args
from netaddr import EUI
from netmiko.hp.hp_comware import HPComwareBase

from .utils.helpers import (
    canonical_interface_name_comware,
    get_value_from_list_of_dict,
    parse_time,
    strptime,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")


VersionInfo: TypeAlias = Dict[str, Union[str, int]]


MACAddress = NewType("MACAddress", str)
SerialNumber = NewType("SerialNumber", str)


class DeviceManuinfoItem(TypedDict):
    chassis_id: str
    slot_type: Literal["Slot", "Fan", "Power"]
    slot_id: str
    device_name: Optional[str]
    serial_number: Optional[SerialNumber]
    manufacturing_date: Optional[str]
    vendor_name: Optional[str]
    mac_address: Optional[MACAddress]


class MacMoveEntry(TypedDict):
    mac: str
    vlan: int
    current_port: str
    source_port: str
    last_move: str
    moves: int


class ComwareDriver(NetworkDriver):
    def __init__(
        self, hostname: str, username: str, password: str, timeout: int = 100, optional_args: Optional[Dict] = None
    ):
        self.device = None  # type: ignore
        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.netmiko_optional_args = netmiko_args(optional_args)

    def open(self) -> None:
        """Open a connection to the device."""
        device_type = "hp_comware"  # for H3C device, this must be hp_comware
        self.device: HPComwareBase = self._netmiko_open(device_type, netmiko_optional_args=self.netmiko_optional_args)

    def close(self) -> None:
        self._netmiko_close()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def send_command(self, command: str, *args, **kwargs) -> str | List[Any] | Dict[str, Any]:
        return self.device.send_command(command, *args, **kwargs)

    def is_alive(self) -> models.AliveDict:
        try:
            return {"is_alive": False if self.device is None else getattr(self.device, "is_alive", lambda: False)()}
        except Exception as e:
            logging.warning(f"Device alive check failed: {str(e)}")
            return {"is_alive": False}

    def _get_structured_output(self, command: str, template_name: Optional[str] = None):
        if template_name is None:
            template_name = "_".join(command.split())
        raw_output = self.send_command(command)
        result = textfsm_extractor(self, template_name, raw_output)  # type: ignore
        return result

    def get_facts(self) -> models.FactsDict:
        """
        Returns a dictionary containing the following information:
         * uptime - Uptime of the device in seconds.
         * vendor - Manufacturer of the device.
         * model - Device model.
         * hostname - Hostname of the device
         * fqdn - Fqdn of the device
         * os_version - String with the OS version running on the device.
         * serial_number - Serial number of the device
         * interface_list - List of the interfaces of the device

        Example::

            {
            'uptime': 151005.57332897186,
            'vendor': u'Arista',
            'os_version': u'4.14.3-2329074.gaatlantarel',
            'serial_number': u'SN0123A34AS',
            'model': u'vEOS',
            'hostname': u'eos-router',
            'fqdn': u'eos-router',
            'interface_list': [u'Ethernet2', u'Management1', u'Ethernet1', u'Ethernet3']
            }

        """

        def _safe_get(data: Optional[Dict], key: str, default: Union[str, float] = "") -> Union[str, float]:
            """Safe dictionary value extraction with type preservation."""
            if not data or key not in data:
                return default
            return data[key] if data[key] is not None else default

        try:
            version = self._get_version() or {}
            hostname = self.device.find_prompt()[1:-1]
            manuinfo = self._get_device_manuinfo() or []
            interfaces = self.get_interfaces() or {}
        except Exception as e:
            raise ValueError(f"Data collection failed: {str(e)}") from e

        serials = []
        for item in manuinfo:
            if isinstance(item, dict) and "serial_number" in item:
                sn = str(item["serial_number"]).strip()
                if sn:
                    serials.append(sn)

        interface_list = [str(iface) for iface in interfaces.keys() if iface and not iface.startswith(("_", "__"))]

        return {
            "uptime": float(_safe_get(version, "uptime", 0.0)),
            "vendor": str(_safe_get(version, "vendor")),
            "os_version": str(_safe_get(version, "os_version")),
            "model": str(_safe_get(version, "model")),
            "hostname": hostname,
            "serial_number": ",".join(serials) if serials else "",
            "fqdn": hostname,  # Default to hostname if FQDN not available
            "interface_list": interface_list,
        }

    def _get_dns_host(self) -> List[Dict[str, Any]]:
        """
        This model's fpdn cannot be got.
        """
        cmd = "display dns host"
        structured_output = self._get_structured_output(cmd)
        return structured_output

    def _get_version(self) -> Optional[VersionInfo]:
        """
        Get device version information including OS version, vendor, uptime and model.

        Returns:
            Optional dictionary containing:
                - os_version (str): Operating system version
                - vendor (str): Device vendor/manufacturer
                - uptime (timedelta): Device uptime duration
                - model (str): Device model
            Returns None if version information cannot be retrieved.
        """
        cmd = "display version"
        structured_output = self._get_structured_output(cmd)

        logging.debug(f"Structured version info: {structured_output}")

        if not isinstance(structured_output, list) or len(structured_output) != 1:
            logging.error(f"Unexpected version output format: {structured_output}")
            return None

        try:
            version_info = structured_output[0]
            (uptime_str, vendor, model, os_version) = itemgetter("uptime", "vendor", "model", "os_version")(
                version_info
            )

            uptime = parse_time(uptime_str)
            if not all([uptime, vendor, model, os_version]):
                raise ValueError("Missing required version fields")

            return {"os_version": os_version, "vendor": vendor, "uptime": uptime, "model": model}

        except (KeyError, ValueError, TypeError) as e:
            logging.error(f"Failed to parse version info: {str(e)}")
            return None

    def _get_device_manuinfo(self) -> List[DeviceManuinfoItem]:
        cmd = "display device manuinfo"
        structured_output = self._get_structured_output(cmd)
        result = []
        for item in structured_output:
            normalized = {
                "chassis_id": item.get("chassis_id", ""),
                "slot_type": item["slot_type"],
                "slot_id": item["slot_id"],
                "device_name": item["device_name"] or None,
                "serial_number": SerialNumber(item["serial_number"]) if item["serial_number"] else None,
                "manufacturing_date": item["manufacturing_date"],
                "vendor_name": item["vendor_name"] or None,
                "mac_address": MACAddress(item["mac_address"]) if item["mac_address"] else None,
            }
            result.append(normalized)
        return result

    def get_interfaces(self) -> Dict[str, models.InterfaceDict]:
        interface_dict: Dict[str, models.InterfaceDict] = {}
        structured_int_info = self._get_structured_output("display interface")
        if not structured_int_info:
            return interface_dict

        for interface in structured_int_info:
            try:
                interface_name = interface.get("interface", "")
                if not interface_name:
                    continue

                is_enabled, is_up = self._parse_interface_status(interface)

                interface_data: models.InterfaceDict = {
                    "is_enabled": is_enabled,
                    "is_up": is_up,
                    "description": self._parse_description(interface.get("description")),
                    "speed": self._parse_bandwidth(interface.get("bandwidth")),
                    "mtu": self._parse_mtu(interface.get("mtu")),
                    "mac_address": self._parse_mac(interface.get("mac_address")),
                    "last_flapped": self._parse_flapping(interface.get("last_flapping")),
                }
                interface_dict[interface_name] = interface_data

            except Exception as e:
                logging.warning(f"Error processing interface {interface.get('interface')}: {e}")
                continue

        return interface_dict

    def _parse_interface_status(self, interface: Dict[str, str]) -> tuple[bool, bool]:
        link_status = interface.get("link_status", "").lower()
        protocol_status = interface.get("protocol_status", "").lower()
        is_enabled = "up" in link_status
        protocol_status_split = protocol_status.split()
        if len(protocol_status_split) == 0:
            logging.warning(f"cannot get up status for interface: {interface}")
            is_up = False
        else:
            is_up = "up" in protocol_status_split[0]
        return (is_enabled, is_up)

    def _parse_description(self, description: Optional[str]) -> str:
        return description if description else ""

    def _parse_bandwidth(self, bandwidth_str: Optional[str]) -> int:
        try:
            return int(bandwidth_str) if bandwidth_str else -1
        except (ValueError, TypeError):
            return -1

    def _parse_mtu(self, mtu_str: Optional[str]) -> int:
        try:
            return int(mtu_str) if mtu_str else -1
        except (ValueError, TypeError):
            return -1

    def _parse_mac(self, mac_str: Optional[str]) -> str:
        return mac_str.lower() if mac_str else "unknown"

    def _parse_flapping(self, flapping_str: Optional[str]) -> Union[int, float]:
        if not flapping_str:
            return -1
        flapping_str = flapping_str.lower()
        if "never" in flapping_str:
            return 0
        try:
            return self._parse_time(flapping_str)
        except Exception:
            return -1

    def _parse_time(self, time_str: str) -> int:
        return parse_time(time_str)

    def get_lldp_neighbors(self) -> Dict[str, List[models.LLDPNeighborDict]]:
        """Retrieve LLDP neighbors information with enhanced reliability.

        Returns:
            Dictionary where keys are local interface names and values are lists
            of neighbor dictionaries containing:
                - hostname: str
                - port: str

        Raises:
            CommandErrorException: If LLDP command execution fails
            ValueError: If data parsing fails
        """
        try:
            command = "display lldp neighbor-information verbose"
            structured_output = self._get_structured_output(command) or []
        except Exception as e:
            raise CommandErrorException(f"LLDP command failed: {str(e)}") from e

        get_neighbor_fields = itemgetter("local_interface", "remote_system_name", "remote_port")

        lldp_neighbors: Dict[str, List[models.LLDPNeighborDict]] = {}

        for entry in structured_output:
            try:
                local_if, remote_name, remote_port = get_neighbor_fields(entry)

                if not all((local_if, remote_name, remote_port)):
                    continue

                neighbor = {"hostname": str(remote_name).strip(), "port": str(remote_port).strip()}

                lldp_neighbors.setdefault(str(local_if).strip(), []).append(neighbor)

            except (KeyError, TypeError) as e:
                continue
            except Exception as e:
                raise ValueError(f"LLDP data parsing error: {str(e)}") from e

        return lldp_neighbors

    def _get_memory(self, verbose=True):
        memory = {}
        command = "display memory"
        structured_output = self._get_structured_output(command)
        for mem_entry in structured_output:
            (chassis, slot, total, used, free, free_ratio) = itemgetter(
                "chassis", "slot", "total", "used", "free", "free_ratio"
            )(mem_entry)

            if chassis != "":
                memory_key = f"chassis {chassis} slot {slot}"
            elif chassis == "" and slot != "":
                memory_key = f"slot {slot}"

            memory[memory_key] = {
                "total_ram": int(total),
                "used_ram": int(used),
                "available_ram": int(free),
                "free_ratio": float(free_ratio),
            }

        if verbose:
            return memory
        else:
            # 为了适配 napalm api（只支持回显一条信息），如果有多个板卡的话，只返回使用空间最多的
            # return info of the slot with max memory usage if device has more than one slot.
            _mem = {}
            _ = get_value_from_list_of_dict(list(memory.values()), "free_ratio", min)
            _mem["used_ram"] = _.get("used_ram")
            _mem["available_ram"] = _.get("available_ram")
            return _mem

    def _get_power(self, verbose=True):
        # 盒式设备只有 Slot，框式设备只有 Chassis
        power = {}
        command = "display power"
        structured_output = self._get_structured_output(command)
        for power_entry in structured_output:
            (
                chassis,
                slot,
                power_id,
                status,
                output,
            ) = itemgetter(
                "chassis", "slot", "power_id", "status", "power"
            )(power_entry)

            if not verbose:
                status = True if status.lower() == "normal" else False

            if slot != "":
                power_key = "slot %s power %s" % (slot, power_id)
            elif chassis != "":
                power_key = "chassis %s power %s" % (chassis, power_id)
            else:
                power_key = "power %s" % (power_id)

            power[power_key] = {"status": status, "capacity": -1, "output": output}
        return power

    def _get_cpu(self, verbose=True):
        cpu = {}
        command = "display cpu-usage summary"
        structured_output = self._get_structured_output(command)
        for cpu_entry in structured_output:
            (chassis, slot, cpu_id, five_sec, one_min, five_min) = itemgetter(
                "chassis", "slot", "cpu_id", "five_sec", "one_min", "five_min"
            )(cpu_entry)

            if chassis != "":
                cpu_key = "Chassis %s Slot %s cpu %s" % (chassis, slot, cpu_id)
            elif chassis == "" and slot != "":
                cpu_key = "Slot %s cpu %s" % (slot, cpu_id)
            else:
                cpu_key = "cpu %s" % (cpu_id)

            if verbose:
                cpu[cpu_key] = {
                    "five_sec": float(five_sec),
                    "one_min": float(one_min),
                    "five_min": float(five_min),
                }
            else:
                cpu[cpu_key] = {
                    r"%usage": float(max([five_sec, one_min, five_min])),
                }
        return cpu

    def _get_fan(self):
        fans = {}
        command = "display fan"
        structured_output = self._get_structured_output(command)
        for fan_entry in structured_output:
            (
                chassis,
                slot,
                fan_id,
                status,
            ) = itemgetter(
                "chassis",
                "slot",
                "fan_id",
                "status",
            )(fan_entry)
            status = True if status.lower() == "normal" else False
            if slot != "":
                fan_key = "Slot %s Fan %s" % (slot, fan_id)
            elif chassis != "":
                fan_key = "Chassis %s Fan %s" % (chassis, fan_id)
            else:
                fan_key = "Fan %s" % (fan_id)
            fans[fan_key] = {"status": status}
        return fans

    def _get_temperature(self):
        temperature = {}
        command = "display environment"
        structured_output = self._get_structured_output(command)
        for temp_entry in structured_output:
            (chassis, slot, sensor, temp, alert, critical) = itemgetter(
                "chassis", "slot", "sensor", "temperature", "alert", "critical"
            )(temp_entry)
            is_alert = True if float(temp) >= float(alert) else False
            is_critical = True if float(temp) >= float(critical) else False

            if chassis != "":
                temp_key = "chassis %s slot %s sensor %s" % (chassis, slot, sensor)
            else:
                temp_key = "slot %s sensor %s" % (slot, sensor)
            temperature[temp_key] = {
                "temperature": float(temp),
                "is_alert": is_alert,
                "is_critical": is_critical,
            }

        return temperature

    def get_environment(self):
        environment = {}

        cpu = self._get_cpu(verbose=False)
        environment["cpu"] = cpu

        memory = self._get_memory(verbose=False)
        environment["memory"] = memory

        power = self._get_power(verbose=False)
        environment["power"] = power

        fans = self._get_fan()
        environment["fans"] = fans

        temperature = self._get_temperature()
        environment["temperature"] = temperature

        return environment

    def get_lldp_neighbors_detail(self, interface: str = ""):
        lldp = {}
        # `parent_interface` is not supported
        parent_interface = ""

        if interface:
            command = "display lldp neighbor-information interface %s verbose" % (interface)
        else:
            command = "display lldp neighbor-information verbose"

        structured_output = self._get_structured_output(command, "display_lldp_neighbor-information_verbose")

        for lldp_entry in structured_output:
            (
                local_interface,
                remote_port,
                remote_port_description,
                remote_chassis_id,
                remote_system_name,
                remote_system_description,
                remote_system_capab,
                remote_system_enabled_capab,
            ) = itemgetter(
                "local_interface",
                "remote_port",
                "remote_port_desc",
                "remote_chassis_id",
                "remote_system_name",
                "remote_system_desc",
                "remote_system_capab",
                "remote_system_enabled_capab",
            )(
                lldp_entry
            )
            _ = {
                "parent_interface": parent_interface,
                "remote_port": remote_port,
                "remote_port_description": remote_port_description,
                "remote_chassis_id": remote_chassis_id,
                "remote_system_name": remote_system_name,
                "remote_system_description": "".join(remote_system_description),
                "remote_system_capab": [i.strip() for i in remote_system_capab.split(",")],
                "remote_system_enabled_capab": [i.strip() for i in remote_system_enabled_capab.split(",")],
            }
            if lldp.get(local_interface) is None:
                lldp[local_interface] = [_]
            else:
                lldp[local_interface].append(_)
        return lldp

    def cli(self, commands: List, encoding: str = "text") -> Dict[str, Union[str, Dict[str, Any]]]:
        cli_output = dict()

        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            output = self.device.send_command(command)
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

    def get_arp_table(self, vrf: str = ""):
        arp_table = []
        if vrf:
            command = "display arp vpn-instance %s" % (vrf)
        else:
            command = "display arp"
        structured_output = self._get_structured_output(command, "display_arp")
        for arp_entry in structured_output:
            (
                interface,
                mac_address,
                ip,
                age,
            ) = itemgetter(
                "interface", "mac_address", "ip_address", "aging"
            )(arp_entry)
            entry = {
                "interface": canonical_interface_name_comware(interface),
                "mac": mac(mac_address),
                "ip": ip,
                "age": float(age),
            }
            arp_table.append(entry)
        return arp_table

    def get_interfaces_ip(self) -> Dict[str, models.InterfacesIPDict]:
        interfaces: Dict[str, models.InterfacesIPDict] = {}
        command = "display ip interface"

        try:
            structured_output = self._get_structured_output(command)
        except Exception as e:
            raise RuntimeError(f"Failed to execute '{command}': {str(e)}") from e

        for iface_entry in structured_output:
            try:
                interface: str
                ip_list: List[str]
                interface, ip_list = itemgetter("interface", "ip_address")(iface_entry)

                if not ip_list:
                    continue

                ipv4: Dict[str, models.InterfacesIPDictEntry] = {}
                for ip_entry in ip_list:
                    try:
                        ip, prefix = ip_entry.split("/")
                        ipv4[ip] = {"prefix_length": int(prefix)}
                    except (ValueError, IndexError) as e:
                        continue

                if ipv4:
                    interfaces[interface] = {"ipv4": ipv4}

            except KeyError as e:
                continue

        return interfaces

    def get_mac_address_move_table(self) -> List[MacMoveEntry]:
        """Retrieve MAC address move table information.

        Returns:
            A list of dictionaries containing MAC move entries with:
            - mac: Normalized MAC address (str)
            - vlan: VLAN ID (int)
            - current_port: Canonical interface name (str)
            - source_port: Canonical interface name (str)
            - last_move: Timestamp of last move (str)
            - moves: Number of moves (int)

        Raises:
            RuntimeError: If command execution fails
            ValueError: If data parsing fails
        """
        command = "display mac-address mac-move"
        try:
            structured_output = self._get_structured_output(command)
        except Exception as e:
            raise RuntimeError(f"Failed to execute '{command}': {str(e)}") from e

        mac_address_move_table: List[MacMoveEntry] = []
        field_getter = itemgetter("mac_address", "vlan", "current_port", "source_port", "last_move", "times")

        for mac_move_entry in structured_output:
            try:
                (
                    mac_address,
                    vlan,
                    current_port,
                    source_port,
                    last_move,
                    moves,
                ) = field_getter(mac_move_entry)

                # Create normalized entry
                entry: MacMoveEntry = {
                    "mac": str(EUI(mac_address)),
                    "vlan": int(vlan),
                    "current_port": canonical_interface_name_comware(current_port),
                    "source_port": canonical_interface_name_comware(source_port),
                    "last_move": last_move.strip(),
                    "moves": int(moves),
                }
                mac_address_move_table.append(entry)

            except (KeyError, ValueError, AttributeError) as e:
                # here we should show warning or log error
                print(f"error: {e}")
                continue

        return mac_address_move_table

    def get_mac_address_table(self):
        mac_address_table = []
        command = "display mac-address"
        structured_output = self._get_structured_output(command)
        mac_address_move_table = self.get_mac_address_move_table()

        def _get_mac_move(mac_address, mac_address_move_table):
            last_move = float(-1)
            moves = -1
            for mac_move in mac_address_move_table:
                if mac_address == mac_move.get("mac_address"):
                    last_move = strptime(mac_move.get("last_move"))
                    moves = mac_move.get("times")
            return {"last_move": float(last_move), "moves": int(moves)}

        for mac_entry in structured_output:
            (mac_address, vlan, state, interface) = itemgetter("mac_address", "vlan", "state", "interface")(mac_entry)
            entry = {
                "mac": mac(mac_address),
                "interface": canonical_interface_name_comware(interface),
                "vlan": int(vlan),
                "static": True if "tatic" in state.lower() else False,
                "state": state,
                "active": True,
            }
            entry.update(_get_mac_move(mac_address, mac_address_move_table))
            mac_address_table.append(entry)

        return mac_address_table

    def get_route_to(self, destination="", protocol="", longer=False):
        ...

    def get_config(self, retrieve="all", full=False, sanitized=False):
        configs = {"startup": "", "running": "", "candidate": ""}
        # Not Supported
        if full:
            pass
        if retrieve.lower() in ("running", "all"):
            command = "display current-configuration"
            configs["running"] = self.send_command(command)
        if retrieve.lower() in ("startup", "all"):
            command = "display saved-configuration"
            configs["startup"] = self.send_command(command)
        # Ignore, plaintext will be encrypted.
        # Remove secret data ? Not Implemented.
        if sanitized:
            pass
        return configs

    def get_network_instances(self, name: str = ""):
        ...

    def get_vlans(self):
        """
        Return structure being spit balled is as follows.
            * vlan_id (int)
                * name (text_type)
                * interfaces (list)

        By default, `vlan_name` == `vlan_description`. If both are default or not, \
        use `vlan_name`. If one of them is not the default value, use user-configured \
        value.

        Example::

            {
                1: {
                    "name": "default",
                    "interfaces": ["GigabitEthernet0/0/1", "GigabitEthernet0/0/2"]
                },
                2: {
                    "name": "vlan2",
                    "interfaces": []
                }
            }
        """
        vlans = {}
        command = "display vlan all"
        structured_output = self._get_structured_output(command)
        for vlan_entry in structured_output:
            vlan_name = vlan_entry.get("name")
            vlan_desc = vlan_entry.get("description")
            vlans[int(vlan_entry.get("vlan_id"))] = {
                "name": vlan_desc if "VLAN " not in vlan_desc and "VLAN " in vlan_name else vlan_name,
                "interfaces": vlan_entry.get("interfaces"),
            }
        return vlans

    def get_irf_config(self):
        """
        Returns a dictionary of dictionaries where the first key is irf member ID,
        and the internal dictionary uses the irf port type as the key and port member as the value.

        Example::
            {
                1: {
                    'irf-port1': ['FortyGigE1/0/53', 'FortyGigE1/0/54'],
                    'irf-port2': [],
                }
                2: {
                    'irf-port1': [],
                    'irf-port2': ['FortyGigE2/0/53', 'FortyGigE2/0/54'],
                }
            }
        """
        irf_config = defaultdict(dict)
        command = "display current-configuration configuration irf-port"
        structured_output = self._get_structured_output(command)
        for config in structured_output:
            (member_id, port_id, port_member) = itemgetter("member_id", "port_id", "port_member")(config)
            irf_config[int(member_id)]["irf-port%s" % port_id] = port_member
        return irf_config

    def is_irf(self):
        """
        Returns True if the IRF is setup.
        """
        config = self.get_irf_config()
        if config:
            return {"is_irf": True}
        else:
            return {"is_irf": False}
