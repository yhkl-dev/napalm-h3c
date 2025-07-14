import logging
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from operator import itemgetter
from typing import Any, DefaultDict, Dict, List, Literal, Optional, Union, cast

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

from .types import (
    ArpEntry,
    CompactMemory,
    CpuDict,
    DeviceManuinfoItem,
    EnvironmentDict,
    FanDict,
    FanInfo,
    IrfConfigDict,
    IrfPortConfig,
    MACAddress,
    MacMoveEntry,
    MemoryEntry,
    MemoryResult,
    PowerDict,
    SerialNumber,
    TemperatureDict,
    TemperatureInfo,
    VerboseCpuInfo,
    VersionInfo,
)
from .utils.helpers import (
    canonical_interface_name_comware,
    parse_time,
    strptime,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")


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
        self._env_cache: Optional[EnvironmentDict] = None
        self._cache_ttl = 30
        self._last_update_time = 0

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

                neighbor: models.LLDPNeighborDict = {
                    "hostname": str(remote_name).strip(),
                    "port": str(remote_port).strip(),
                }

                lldp_neighbors.setdefault(str(local_if).strip(), []).append(neighbor)

            except (KeyError, TypeError) as e:
                continue
            except Exception as e:
                raise ValueError(f"LLDP data parsing error: {str(e)}") from e

        return lldp_neighbors

    def _get_memory(self, verbose: Literal[True, False] = True) -> MemoryResult:
        """获取设备内存信息(支持多板卡场景)

        Args:
            verbose: 是否返回详细的多板卡信息

        Returns:
            当 verbose=True 时返回包含所有板卡详细信息的字典
            当 verbose=False 时返回内存压力最大的板卡摘要信息

        Raises:
            CommandError: 设备命令执行失败时抛出
            ValueError: 数据解析异常时抛出
        """
        memory: Dict[str, MemoryEntry] = {}
        required_fields = ("chassis", "slot", "total", "used", "free", "free_ratio")

        try:
            structured_output = self._get_structured_output("display memory")
            if not isinstance(structured_output, list):
                raise ValueError("Invalid memory data format")

            get_mem_fields = itemgetter(*required_fields)

            for entry in structured_output:
                try:
                    chassis, slot, total, used, free, ratio = (str(field).strip() for field in get_mem_fields(entry))

                    if not all((total.isdigit(), used.isdigit(), free.isdigit())):
                        continue

                    memory_key = f"chassis {chassis} slot {slot}" if chassis else f"slot {slot}" if slot else "default"

                    memory[memory_key] = MemoryEntry(
                        total_ram=int(total),
                        used_ram=int(used),
                        available_ram=int(free),
                        free_ratio=float(ratio.strip("%")) if "%" in ratio else float(ratio),
                    )

                except (ValueError, AttributeError, KeyError):
                    continue

        except Exception as e:
            raise CommandErrorException(f"Memory collection failed: {str(e)}") from e

        if verbose or not memory:
            return memory

        most_used = max(
            memory.items(),
            key=lambda x: (x[1]["used_ram"] / x[1]["total_ram"]),
            default=(None, MemoryEntry(total_ram=0, used_ram=0, available_ram=0, free_ratio=0.0)),
        )

        return CompactMemory(used_ram=most_used[1]["used_ram"], available_ram=most_used[1]["available_ram"])

    def _get_power(self) -> PowerDict:
        """
        获取设备电源信息

        Returns:
            电源信息字典,格式为:
            {
                "slot 1 power 1": {
                    "status": True,  # 或"Normal"
                    "capacity": -1,
                    "output": "12.5V"
                },
                ...
            }
        """
        power: PowerDict = {}
        command = "display power"
        structured_output = self._get_structured_output(command)

        for power_entry in structured_output:
            entry = itemgetter("chassis", "slot", "power_id", "status", "power")(power_entry)
            chassis, slot, power_id, status, output = entry

            processed_status = status.lower() == "normal"

            power_key = self._build_power_key(chassis, slot, power_id)

            try:
                capacity = int(float(output.split()[0])) if output else -1
            except (ValueError, AttributeError):
                capacity = -1

            power[power_key] = {"status": processed_status, "capacity": capacity, "output": output}

        return power

    def _build_power_key(self, chassis: str, slot: str, power_id: str) -> str:
        """
        构建电源信息的键名

        Args:
            chassis: 机箱编号
            slot: 插槽编号
            power_id: 电源ID

        Returns:
            格式化后的键名字符串
        """
        if slot:
            return f"slot {slot} power {power_id}"
        if chassis:
            return f"chassis {chassis} power {power_id}"
        return f"power {power_id}"

    def _get_cpu(self, verbose: bool = True) -> models.CPUDict:
        """
        获取设备CPU使用率信息

        Args:
            verbose: 返回详细数据(True返回三个时间维度的数据, False返回峰值使用率)

        Returns:
            CPU信息字典, 格式为:
            verbose模式:
            {
                "Chassis 1 Slot 2 cpu 0": {
                    "five_sec": 15.2,
                    "one_min": 12.3,
                    "five_min": 10.1
                }
            }
            非verbose模式:
            {
                "Slot 3 cpu 1": {
                    "%usage": 25.5  # 三个时间段中的最大值
                }
            }
        """
        cpu: models.CPUDict = {"%usage": 0}
        command = "display cpu-usage summary"
        structured_output = self._get_structured_output(command)

        for cpu_entry in structured_output:
            entry = itemgetter("chassis", "slot", "cpu_id", "five_sec", "one_min", "five_min")(cpu_entry)
            chassis, slot, cpu_id, five_sec, one_min, five_min = entry

            cpu_key = self._build_cpu_key(chassis, slot, cpu_id)

            try:
                five_sec_f = float(five_sec)
                one_min_f = float(one_min)
                five_min_f = float(five_min)
            except (ValueError, TypeError) as e:
                continue

            if verbose:
                cpu[cpu_key] = VerboseCpuInfo(five_sec=five_sec_f, one_min=one_min_f, five_min=five_min_f)
            else:
                cpu[cpu_key] = {"%usage": max(five_sec_f, one_min_f, five_min_f)}

        return cpu

    def _build_cpu_key(self, chassis: str, slot: str, cpu_id: str) -> str:
        """
        构建CPU信息的键名

        Args:
            chassis: 机箱编号
            slot: 插槽编号
            cpu_id: CPU标识符

        Returns:
            格式化后的键名字符串
        """
        if chassis:
            return f"Chassis {chassis} Slot {slot} cpu {cpu_id}"
        elif slot:
            return f"Slot {slot} cpu {cpu_id}"
        return f"cpu {cpu_id}"

    def _get_fan(self) -> FanDict:
        """
        获取设备风扇状态信息

        Returns:
            风扇信息字典,格式为:
            {
                "Slot 1 Fan 2": {
                    "status": True  # True表示正常(Normal)
                },
                "Chassis 2 Fan 3": {
                    "status": False  # False表示异常
                }
            }
        """
        fans: FanDict = {}
        command = "display fan"
        structured_output = self._get_structured_output(command)

        for fan_entry in structured_output:
            chassis, slot, fan_id, status = itemgetter("chassis", "slot", "fan_id", "status")(fan_entry)

            fan_key = self._build_fan_key(chassis, slot, fan_id)

            status_bool = status.lower() == "normal"
            fans[fan_key] = FanInfo(status=status_bool)

        return fans

    def _build_fan_key(self, chassis: str, slot: str, fan_id: str) -> str:
        """
        构建风扇信息的键名

        Args:
            chassis: 机箱编号
            slot: 插槽编号
            fan_id: 风扇标识符

        Returns:
            格式化后的键名字符串
        """
        if slot:
            return f"Slot {slot} Fan {fan_id}"
        elif chassis:
            return f"Chassis {chassis} Fan {fan_id}"
        return f"Fan {fan_id}"

    def _get_temperature(self) -> TemperatureDict:
        """
        获取设备温度传感器信息

        Returns:
            温度信息字典,格式为:
            {
                "chassis 1 slot 2 sensor 3": {
                    "temperature": 45.2,
                    "is_alert": True,
                    "is_critical": False
                },
                "slot 4 sensor 1": {
                    "temperature": 38.5,
                    "is_alert": False,
                    "is_critical": False
                }
            }
        """
        temperature: TemperatureDict = {}
        command = "display environment"
        structured_output = self._get_structured_output(command)

        for temp_entry in structured_output:
            chassis, slot, sensor, temp, alert, critical = itemgetter(
                "chassis", "slot", "sensor", "temperature", "alert", "critical"
            )(temp_entry)

            try:
                temp_f = float(temp)
                alert_f = float(alert)
                critical_f = float(critical)
            except (ValueError, TypeError):
                continue

            temp_key = self._build_temp_key(chassis, slot, sensor)

            temperature[temp_key] = TemperatureInfo(
                temperature=temp_f, is_alert=temp_f >= alert_f, is_critical=temp_f >= critical_f
            )

        return temperature

    def _build_temp_key(self, chassis: str, slot: str, sensor: str) -> str:
        """
        构建温度信息的键名

        Args:
            chassis: 机箱编号
            slot: 插槽编号
            sensor: 传感器标识符

        Returns:
            格式化后的键名字符串
        """
        if chassis:
            return f"chassis {chassis} slot {slot} sensor {sensor}"
        return f"slot {slot} sensor {sensor}"

    def get_environment(self, use_cache: bool = True) -> EnvironmentDict:  # type: ignore
        """
        获取设备环境数据(并行采集各子系统数据)

        Args:
            use_cache: 是否使用缓存数据(默认True), 设置为False强制刷新

        Returns:
            环境数据字典,结构为:
            {
                "cpu": Dict[str, Any],         # CPU使用率数据
                "memory": Dict[str, Any],      # 内存使用数据
                "power": Dict[str, Any],       # 电源状态数据
                "fans": Dict[str, Any],        # 风扇状态数据
                "temperature": Dict[str, Any]  # 温度传感器数据
            }

        Raises:
            EnvironmentError: 当任何子系统数据获取失败时
        """
        if use_cache and self._is_cache_valid():
            assert self._env_cache
            return self._env_cache

        try:
            with ThreadPoolExecutor(max_workers=5) as executor:
                get_data = partial(self._get_subsystem_data, verbose=False)

                future_cpu = executor.submit(get_data, "_get_cpu")
                future_mem = executor.submit(get_data, "_get_memory")
                future_power = executor.submit(self._get_power)
                future_fans = executor.submit(self._get_fan)
                future_temp = executor.submit(self._get_temperature)

                environment = EnvironmentDict(
                    cpu=future_cpu.result(),
                    memory=future_mem.result(),
                    power=future_power.result(),
                    fans=future_fans.result(),
                    temperature=future_temp.result(),
                )

            self._env_cache = environment
            self._last_update_time = time.time()

        except Exception as e:
            logging.error(f"Environment data collection failed: {str(e)}")
            raise EnvironmentError("Failed to collect environment data") from e

        return environment

    def _get_subsystem_data(self, method_name: str, **kwargs) -> Dict[str, Any]:
        try:
            method = getattr(self, method_name)
            return method(**kwargs)
        except Exception as e:
            logging.error(f"Failed to get {method_name} data: {str(e)}")
            return {}

    def _is_cache_valid(self) -> bool:
        return self._env_cache is not None and (time.time() - self._last_update_time) < self._cache_ttl

    def clear_cache(self):
        self._env_cache = None
        self._last_update_time = 0

    def get_lldp_neighbors_detail(self, interface: str = ""):
        lldp = {}
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

    def get_arp_table(self, vrf: str = "") -> List[ArpEntry]:
        """获取ARP表信息(支持VRF)

        Args:
            vrf: 可选参数, 指定VRF实例名称。默认为全局路由表

        Returns:
            标准化ARP条目列表, 每个条目包含:
            - interface: 规范化后的接口名
            - mac: 标准化的MAC地址
            - ip: IP地址
            - age: 老化时间(秒)

        Raises:
            CommandErrorException: CLI命令执行失败时
            ValueError: 数据解析失败时
        """
        command = f"display arp vpn-instance {vrf}" if vrf else "display arp"
        try:
            structured_output: List[Dict[str, str]] = self._get_structured_output(command, template_name="display_arp")
        except Exception as e:
            raise CommandErrorException(f"ARP command excute error: {command}") from e

        arp_table: List[ArpEntry] = []
        required_fields = ("interface", "mac_address", "ip_address", "aging")
        get_fields = itemgetter(*required_fields)

        for arp_entry in structured_output:
            try:
                interface, mac_addr, ip, age = get_fields(arp_entry)
                entry: ArpEntry = {
                    "interface": canonical_interface_name_comware(interface),
                    "mac": mac(mac_addr),
                    "ip": ip,
                    "age": float(age),
                }
                arp_table.append(entry)
            except (KeyError, ValueError) as e:
                raise ValueError(f"无效ARP条目: {arp_entry}") from e

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
                logging.warning(f"error when execute command: {command},error: {e}")
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

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """
        获取设备配置信息

        Args:
            retrieve: 要检索的配置类型,可选值为:
                - "all": 获取所有配置(默认)
                - "running": 只获取运行配置
                - "startup": 只获取启动配置
                - "candidate": 候选配置(暂不支持)
            full: 是否获取完整配置(暂不支持)
            sanitized: 是否对敏感信息进行脱敏处理(暂不支持)
            format: 返回格式,支持 "text" 或 "json"(暂不支持)

        Returns:
            包含配置信息的字典,格式为:
            {
                "startup": str,
                "running": str,
                "candidate": str
            }

        Raises:
            ValueError: 当传入无效的retrieve参数时
        """
        if retrieve.lower() not in ("all", "running", "startup", "candidate"):
            raise ValueError(f"Invalid retrieve value: {retrieve}. Must be one of: all, running, startup, candidate")

        if format.lower() not in ("text", "json"):
            raise ValueError(f"Unsupported format: {format}. Only 'text' or 'json' are supported")

        configs: models.ConfigDict = {"startup": "", "running": "", "candidate": ""}

        try:
            if retrieve.lower() in ("running", "all"):
                command = "display current-configuration"
                configs["running"] = self.send_command(command)  # type: ignore

            if retrieve.lower() in ("startup", "all"):
                command = "display saved-configuration"
                configs["startup"] = self.send_command(command)  # type: ignore

            # TODO: 实现完整配置获取功能
            if full:
                logging.warning("Full config retrieval is not yet implemented")

            # TODO: 实现配置脱敏功能
            if sanitized:
                logging.warning("Config sanitization is not yet implemented")

            # TODO: 实现格式转换功能
            if format.lower() == "json":
                logging.warning("JSON format is not yet implemented")

        except Exception as e:
            logging.error(f"Failed to retrieve config: {str(e)}")
            raise

        return configs

    def get_vlans(self) -> Dict[str, models.VlanDict]:
        """获取设备VLAN信息

        Returns:
            结构化VLAN信息字典,格式:
            {
                vlan_id(int): {
                    "name": str,          # VLAN名称(优先使用非默认描述)
                    "interfaces": List[str]  # 关联接口列表
                }
            }

        Raises:
            CommandError: 命令执行失败时
            ValueError: 数据解析失败时

        Example:
            {
                1: {
                    "name": "default",
                    "interfaces": ["GigabitEthernet0/0/1"]
                },
                100: {
                    "name": "mgmt_vlan",
                    "interfaces": []
                }
            }
        """
        DEFAULT_VLAN_PREFIX = "VLAN "
        command = "display vlan all"
        try:
            structured_output: List[Dict[str, Union[str, List[str]]]] = self._get_structured_output(command)
        except Exception as e:
            raise CommandErrorException(f"VLAN command execute failed: {command}") from e

        vlans = {}
        required_fields = ("vlan_id", "name", "description", "interfaces")
        get_fields = itemgetter(*required_fields)

        for vlan_entry in structured_output:
            try:
                vlan_id, name, desc, interfaces = get_fields(vlan_entry)
                final_name = (
                    desc if not desc.startswith(DEFAULT_VLAN_PREFIX) and name.startswith(DEFAULT_VLAN_PREFIX) else name
                )

                vlans[vlan_id] = {
                    "name": final_name.strip(),
                    "interfaces": [canonical_interface_name_comware(iface) for iface in interfaces if iface],
                }
            except (KeyError, ValueError, AttributeError) as e:
                raise ValueError(f"invalid vala item: {vlan_entry}") from e

        return vlans

    def get_irf_config(self) -> IrfConfigDict:
        command = "display current-configuration configuration irf-port"
        try:
            structured_output = self._get_structured_output(command)
        except Exception as e:
            raise CommandErrorException(f"IRF配置命令执行失败: {command}") from e

        temp_config: Dict[int, Dict[str, List[str]]] = defaultdict(lambda: {"irf-port1": [], "irf-port2": []})

        for config in structured_output:
            try:
                member_id = int(config["member_id"])
                port_id = str(config["port_id"])
                port_member = config["port_member"] or []
                port_key = f"irf-port{port_id}"

                if port_key not in ("irf-port1", "irf-port2"):
                    continue

                temp_config[member_id][port_key] = [self._normalize_interface(iface) for iface in port_member if iface]
            except (KeyError, ValueError) as e:
                raise ValueError(f"无效IRF配置条目: {config}") from e

        final_config = {
            member_id: cast(IrfPortConfig, {"irf_port1": ports["irf-port1"], "irf_port2": ports["irf-port2"]})
            for member_id, ports in temp_config.items()
        }
        return final_config

    def _normalize_interface(self, interface: str) -> str:
        return interface.strip().replace(" ", "")

    def is_irf(self):
        """
        Returns True if the IRF is setup.
        """
        config = self.get_irf_config()
        if config:
            return {"is_irf": True}
        else:
            return {"is_irf": False}
