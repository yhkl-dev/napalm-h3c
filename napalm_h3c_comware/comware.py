# pyright: reportMissingTypeStubs=false

import difflib
import ipaddress
import logging
import re
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from operator import itemgetter
from pathlib import Path
from types import TracebackType
from typing import Any, Dict, List, Literal, Optional, Type, Union, cast

import napalm.base.helpers as napalm_helpers
import napalm.base.netmiko_helpers as napalm_netmiko_helpers
from napalm.base import models
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import CommandErrorException, CommitError, MergeConfigException, ReplaceConfigException
from napalm.base.helpers import mac
from netmiko.hp.hp_comware import HPComwareBase

from .types import (
    ArpEntry,
    DeviceManuinfoItem,
    EnvironmentDict,
    FanDict,
    IrfConfigDict,
    IrfPortConfig,
    MACAddress,
    MacMoveEntry,
    MemoryEntry,
    PowerDict,
    SerialNumber,
    TemperatureDict,
    VerboseCpuInfo,
    VersionInfo,
)
from .utils.helpers import canonical_interface_name_comware, parse_time, strptime

logger = logging.getLogger(__name__)

StructuredRow = Dict[str, Any]
StructuredOutput = List[StructuredRow]


def _safe_get(data: Optional[Dict[str, Any]], key: str, default: Union[str, float] = "") -> Union[str, float]:
    if not data or key not in data:
        return default
    return data[key] if data[key] is not None else default


def _as_str_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in cast(List[Any], value)]
    return [str(value)]


def _parse_number(value: str) -> Union[int, float]:
    return float(value) if "." in value else int(value)


def _normalize_routing_table_name(name: str) -> str:
    normalized = name.strip()
    if normalized.lower() in {"_public_", "public", "default"}:
        return "global"
    return normalized


def _normalize_outgoing_interface(name: str) -> str:
    return canonical_interface_name_comware(name) if name and name not in {"NULLO", "-"} else name


def _has_cli_error(output: str) -> bool:
    normalized = output.strip()
    if not normalized:
        return False
    if normalized.startswith("%"):
        return True
    if "\n ^" in normalized:
        return True
    lower_output = normalized.lower()
    if lower_output.startswith("error:"):
        return True
    if "\nerror:" in lower_output:
        return True
    error_markers = (
        "incomplete command",
        "ambiguous command",
        "wrong parameter",
        "no such file",
        "too many parameters",
        "unrecognized command",
        "syntax error",
    )
    return any(marker in lower_output for marker in error_markers)


def _parse_directory_timestamps(output: str, target_files: List[str]) -> Dict[str, int]:
    file_timestamps: Dict[str, int] = {}
    target_names = set(target_files)
    pattern = re.compile(
        r"^\s*\d+\s+\S+\s+\S+\s+(?P<timestamp>[A-Z][a-z]{2}\s+\d{2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})\s+(?P<name>\S+)\s*$"
    )
    for line in output.splitlines():
        match = pattern.match(line)
        if match is None:
            continue
        name = match.group("name")
        if name not in target_names:
            continue
        file_timestamps[name] = int(time.mktime(time.strptime(match.group("timestamp"), "%b %d %Y %H:%M:%S")))
    return file_timestamps


def _validate_cli_token(
    value: str, field_name: str, *, allow_network: bool = False, allow_hostname: bool = False
) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} cannot be empty")
    if re.search(r"[\s\x00-\x1f\x7f]", normalized):
        raise ValueError(f"Invalid {field_name}: whitespace and control characters are not allowed")

    try:
        if allow_network:
            ipaddress.ip_network(normalized, strict=False)
        else:
            ipaddress.ip_address(normalized)
        return normalized
    except ValueError:
        if allow_hostname and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,253}[A-Za-z0-9])?", normalized):
            return normalized
        raise ValueError(f"Invalid {field_name}: {value}")


def _validate_int_argument(value: Any, field_name: str, *, minimum: int = 1, maximum: Optional[int] = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"Invalid {field_name}: {value}")
    validated_value = cast(int, value)
    if validated_value < minimum:
        raise ValueError(f"Invalid {field_name}: {value}")
    if maximum is not None and validated_value > maximum:
        raise ValueError(f"Invalid {field_name}: {value}")
    return validated_value


class ComwareDriver(NetworkDriver):
    _DEFAULT_VLAN_PREFIX = "VLAN "
    _BACKUP_CONFIG_FILES = ("backup-before-merge.cfg", "backup-before-replace.cfg")

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        timeout: int = 100,
        optional_args: Optional[Dict[str, Any]] = None,
    ):
        self.device: Optional[HPComwareBase] = None
        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.netmiko_optional_args: Dict[str, Any] = cast(
            Dict[str, Any], cast(Any, napalm_netmiko_helpers).netmiko_args(optional_args)
        )
        self._env_cache: Optional[EnvironmentDict] = None
        self._cache_ttl = 30
        self._last_update_time = 0.0
        self._candidate_config = ""
        self._replace_candidate = False
        self._last_backup_file: Optional[str] = None
        self._device_lock = threading.Lock()
        self._running_config_lines: Optional[List[str]] = None
        self._running_config_text: Optional[str] = None

    def open(self) -> None:
        """Open a connection to the device."""
        device_type = "hp_comware"  # for H3C device, this must be hp_comware
        netmiko_open = getattr(self, "_netmiko_open")
        self.device = cast(HPComwareBase, netmiko_open(device_type, netmiko_optional_args=self.netmiko_optional_args))

    def close(self) -> None:
        self._netmiko_close()

    def __enter__(self) -> "ComwareDriver":
        self.open()
        return self

    def __exit__(
        self,
        _exc_type: Optional[Type[BaseException]],
        _exc_val: Optional[BaseException],
        _exc_tb: Optional[TracebackType],
    ) -> None:
        self.close()

    def send_command(self, command: str, *args: Any, **kwargs: Any) -> str:
        if self.device is None:
            raise CommandErrorException("Device is not connected — call open() first")
        with self._device_lock:
            return str(self.device.send_command(command, *args, **kwargs))

    def send_config_set(self, config_commands: List[str], *args: Any, **kwargs: Any) -> str:
        if self.device is None:
            raise CommandErrorException("Device is not connected — call open() first")
        with self._device_lock:
            return str(self.device.send_config_set(config_commands, *args, **kwargs))

    def find_prompt(self) -> str:
        if self.device is None:
            raise CommandErrorException("Device is not connected — call open() first")
        with self._device_lock:
            return str(self.device.find_prompt())

    def is_alive(self) -> models.AliveDict:
        try:
            return {"is_alive": False if self.device is None else getattr(self.device, "is_alive", lambda: False)()}
        except Exception as e:
            logger.warning(f"Device alive check failed: {str(e)}")
            return {"is_alive": False}

    def ping(
        self,
        destination: str,
        source: str = "",
        ttl: int = 255,
        timeout: int = 2,
        size: int = 100,
        count: int = 5,
        vrf: str = "",
        source_interface: str = "",
    ) -> models.PingResultDict:
        if vrf:
            raise NotImplementedError("VRF-aware ping is not supported on Comware yet")
        if source_interface:
            raise NotImplementedError("source_interface ping is not supported on Comware yet")

        validated_destination = _validate_cli_token(destination, "ping destination", allow_hostname=True)
        validated_source = _validate_cli_token(source, "ping source") if source else ""
        validated_timeout = _validate_int_argument(timeout, "ping timeout")
        validated_size = _validate_int_argument(size, "ping size")
        validated_count = _validate_int_argument(count, "ping count")
        validated_ttl = _validate_int_argument(ttl, "ping ttl", maximum=255)

        command = f"ping -t {validated_timeout * 1000} -s {validated_size} -c {validated_count}"
        if validated_ttl != 255:
            command += f" -h {validated_ttl}"
        if validated_source:
            command += f" -a {validated_source}"
        command += f" {validated_destination}"

        output = self.send_command(command)
        if re.search(r"(?i)\berror\b|unknown host|unreachable", output):
            return {"error": output.strip()}

        sent_match = re.search(r"(\d+)\s+packet\(s\)\s+transmitted", output)
        received_match = re.search(r"(\d+)\s+packet\(s\)\s+received", output)
        if sent_match is None or received_match is None:
            return {"error": output.strip() or "Ping command failed"}

        probes_sent = int(sent_match.group(1))
        probes_received = int(received_match.group(1))
        result: models.PingDict = {
            "probes_sent": probes_sent,
            "packet_loss": (probes_sent - probes_received) / probes_sent * 100 if probes_sent > 0 else 0.0,
            "rtt_min": 0.0,
            "rtt_max": 0.0,
            "rtt_avg": 0.0,
            "rtt_stddev": 0.0,
            "results": [],
        }

        stats_match = re.search(r"min/avg/max(?:/[a-z]+)?\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)", output, re.I)
        if stats_match:
            result["rtt_min"] = float(stats_match.group(1))
            result["rtt_avg"] = float(stats_match.group(2))
            result["rtt_max"] = float(stats_match.group(3))

        probe_results: List[models.PingResultDictEntry] = []
        for ip_addr, operator, rtt_value in re.findall(
            r"Reply from\s+(\S+):.*?time([=<])(\d+(?:\.\d+)?)", output, re.I
        ):
            rtt = float(rtt_value)
            if operator == "<" and rtt == 1.0:
                rtt = 1.0
            probe_results.append({"ip_address": ip_addr, "rtt": rtt})

        result["results"] = probe_results
        return {"success": result}

    def traceroute(
        self,
        destination: str,
        source: str = "",
        ttl: int = 255,
        timeout: int = 2,
        vrf: str = "",
    ) -> models.TracerouteResultDict:
        if vrf:
            raise NotImplementedError("VRF-aware traceroute is not supported on Comware yet")

        validated_destination = _validate_cli_token(destination, "traceroute destination", allow_hostname=True)
        validated_source = _validate_cli_token(source, "traceroute source") if source else ""
        validated_timeout = _validate_int_argument(timeout, "traceroute timeout")
        validated_ttl = _validate_int_argument(ttl, "traceroute ttl", maximum=255)

        command = f"tracert -m {validated_ttl} -w {validated_timeout * 1000}"
        if validated_source:
            command += f" -a {validated_source}"
        command += f" {validated_destination}"

        output = self.send_command(command)
        if re.search(r"(?i)\berror\b|unknown host|unreachable", output):
            return {"error": output.strip()}

        hop_results: Dict[int, models.TracerouteResultDictEntry] = {}
        hop_pattern = re.compile(r"^\s*(\d+)\s+(.+)$")
        rtt_pattern = re.compile(r"(\d+(?:\.\d+)?)\s*ms", re.I)
        ip_pattern = re.compile(r"^\(?([0-9a-f:.]+)\)?$", re.I)

        for line in output.splitlines():
            hop_match = hop_pattern.match(line)
            if hop_match is None:
                continue

            hop_index = int(hop_match.group(1))
            hop_body = hop_match.group(2)
            probes: Dict[int, models.TracerouteDict] = {}
            if re.match(r"^\*[\s*]*$", hop_body.strip()):
                for probe_index in range(1, 4):
                    probes[probe_index] = {"host_name": "*", "ip_address": "*", "rtt": -1.0}
                hop_results[hop_index] = {"probes": probes}
                continue

            parse_pos = 0
            last_host = ""
            last_ip = ""
            while len(probes) < 3:
                remaining = hop_body[parse_pos:].lstrip()
                if not remaining:
                    break
                if remaining.startswith("*"):
                    probe_index = len(probes) + 1
                    probes[probe_index] = {"host_name": "*", "ip_address": "*", "rtt": -1.0}
                    parse_pos = len(hop_body) - len(remaining) + 1
                    continue

                rtt_match = rtt_pattern.search(hop_body, parse_pos)
                if rtt_match is None:
                    break

                prefix = hop_body[parse_pos : rtt_match.start()].strip()
                host_name = last_host
                ip_address = last_ip
                if prefix:
                    prefix = prefix.strip("()")
                    tokens = prefix.split()
                    if tokens:
                        candidate = tokens[-1].strip("()")
                        if ip_pattern.match(candidate):
                            ip_address = candidate
                            host_name = " ".join(token.strip("()") for token in tokens[:-1]).strip() or ip_address
                        else:
                            host_name = " ".join(token.strip("()") for token in tokens)
                            ip_address = host_name

                if not host_name or not ip_address:
                    break

                probe_index = len(probes) + 1
                probes[probe_index] = {
                    "host_name": host_name,
                    "ip_address": ip_address,
                    "rtt": float(rtt_match.group(1)),
                }
                last_host = host_name
                last_ip = ip_address
                parse_pos = rtt_match.end()

            if probes:
                hop_results[hop_index] = {"probes": probes}

        return {"success": hop_results} if hop_results else {"error": output.strip() or "Traceroute command failed"}

    def get_bgp_neighbors(self) -> Dict[str, models.BGPStateNeighborsPerVRFDict]:
        output = self.send_command("display bgp peer")
        if not output.strip():
            return {}

        router_id_match = re.search(r"BGP local router ID\s*:\s*(?P<router_id>\S+)", output, re.I)
        local_as_match = re.search(r"Local AS number\s*:\s*(?P<local_as>\d+)", output, re.I)
        local_as = int(local_as_match.group("local_as")) if local_as_match else 0

        result: Dict[str, models.BGPStateNeighborsPerVRFDict] = {
            "global": {"router_id": router_id_match.group("router_id") if router_id_match else "", "peers": {}}
        }

        peer_pattern = re.compile(
            r"^(?P<peer>\S+)\s+"
            r"(?P<remote_as>\d+)\s+"
            r"(?P<msg_rcvd>\d+)\s+"
            r"(?P<msg_sent>\d+)\s+"
            r"\d+\s+\d+\s+\d+\s+"
            r"(?P<uptime>\S+)\s+"
            r"(?P<state>\S+)\s*$",
            re.M,
        )

        peers: List[tuple[str, str, str, str, bool, bool, int, str]] = []
        for match in peer_pattern.finditer(output):
            peer_ip = match.group("peer")
            state_field = match.group("state")
            state_name, _, prefix_count = state_field.partition("/")
            is_up = state_name.lower() == "established"
            is_enabled = "admin" not in state_name.lower()
            received_prefixes = int(prefix_count) if prefix_count.isdigit() else 0
            address_family = "ipv6 unicast" if ":" in peer_ip else "ipv4 unicast"
            peers.append(
                (
                    peer_ip,
                    match.group("remote_as"),
                    match.group("uptime"),
                    address_family,
                    is_up,
                    is_enabled,
                    received_prefixes,
                    state_name,
                )
            )

        peer_details: Dict[str, str] = {}
        if peers:
            with ThreadPoolExecutor(max_workers=min(len(peers), 10)) as executor:
                futures = {executor.submit(self.send_command, f"display bgp peer {p[0]}"): p[0] for p in peers}
                for future in futures:
                    try:
                        peer_details[futures[future]] = future.result()
                    except Exception:
                        peer_details[futures[future]] = ""

        for peer_ip, remote_as, uptime, address_family, is_up, is_enabled, received_prefixes, _ in peers:
            peer_detail = peer_details.get(peer_ip, "")
            sent_prefixes = 0
            remote_id = ""
            description = ""

            remote_id_match = re.search(r"remote router ID\s+(?P<remote_id>\S+)", peer_detail, re.I)
            if remote_id_match:
                remote_id = remote_id_match.group("remote_id")

            description_match = re.search(
                r"Peer'?s description\s*:\s*\"?(?P<description>.+?)\"?\s*$", peer_detail, re.M
            )
            if description_match:
                description = description_match.group("description").strip()

            sent_prefix_match = re.search(
                r"Advertised(?: total)? routes\s*:\s*(?P<count>\d+)|Sent prefixes\s*:\s*(?P<sent>\d+)",
                peer_detail,
                re.I,
            )
            if sent_prefix_match:
                sent_prefixes = int(sent_prefix_match.group("count") or sent_prefix_match.group("sent") or 0)

            result["global"]["peers"][peer_ip] = {
                "local_as": local_as,
                "remote_as": int(remote_as),
                "remote_id": remote_id,
                "is_up": is_up,
                "is_enabled": is_enabled,
                "description": description,
                "uptime": parse_time(uptime),
                "address_family": {
                    address_family: {
                        "received_prefixes": received_prefixes,
                        "accepted_prefixes": received_prefixes,
                        "sent_prefixes": sent_prefixes,
                    }
                },
            }

        return result

    def get_route_to(
        self, destination: str = "", protocol: str = "", longer: bool = False
    ) -> Dict[str, List[models.RouteDict]]:
        if longer:
            raise NotImplementedError("longer route lookup is not supported on Comware yet")
        if not destination:
            return {}
        validated_destination = _validate_cli_token(destination, "route destination", allow_network=True)
        if ":" in validated_destination:
            raise NotImplementedError("IPv6 route lookup is not supported on Comware yet")

        output = self.send_command(f"display ip routing-table {validated_destination} verbose")
        if not output.strip():
            return {}

        routing_table_match = re.search(r"Routing Table[s]?\s*:\s*(?P<table>\S+)", output, re.I)
        routing_table = (
            _normalize_routing_table_name(routing_table_match.group("table")) if routing_table_match else "global"
        )
        routes: Dict[str, List[models.RouteDict]] = {}
        protocol_filter = protocol.strip().lower()

        table_pattern = re.compile(
            r"^(?P<prefix>\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?)(?:\s+(?P<mask>\d{1,3}(?:\.\d{1,3}){3}))?\s+"
            r"(?P<protocol>\S+)\s+"
            r"(?P<preference>\d+)\s+"
            r"(?P<cost>\d+)\s+"
            r"(?P<flags>[A-Z-]+)\s+"
            r"(?P<next_hop>\S+)\s+"
            r"(?P<interface>\S+)"
            r"(?:\s+(?P<age>\S+))?\s*$",
            re.M,
        )

        for match in table_pattern.finditer(output):
            prefix = match.group("prefix")
            if "/" not in prefix:
                mask = match.group("mask")
                if not mask:
                    continue
                prefix = f"{prefix}/{ipaddress.IPv4Network(f'0.0.0.0/{mask}').prefixlen}"

            route_protocol = match.group("protocol")
            if protocol_filter and route_protocol.lower() != protocol_filter:
                continue

            route: models.RouteDict = {
                "protocol": route_protocol.upper(),
                "current_active": True,
                "last_active": False,
                "age": parse_time(match.group("age") or ""),
                "next_hop": match.group("next_hop"),
                "outgoing_interface": _normalize_outgoing_interface(match.group("interface")),
                "selected_next_hop": "R" not in match.group("flags"),
                "preference": int(match.group("preference")),
                "inactive_reason": "",
                "routing_table": routing_table,
                "protocol_attributes": {"metric": int(match.group("cost"))},
            }
            routes.setdefault(prefix, []).append(route)

        if routes:
            return routes

        for block in re.split(r"\n\s*\n", output):
            destination_match = re.search(r"Destination:\s*(?P<prefix>\S+)", block, re.I)
            protocol_match = re.search(r"Protocol\s*:\s*(?P<protocol>\S+)", block, re.I)
            preference_match = re.search(r"Preference\s*:\s*(?P<preference>\d+)", block, re.I)
            cost_match = re.search(r"Cost\s*:\s*(?P<cost>\d+)", block, re.I)
            next_hop_match = re.search(r"NextHop\s*:\s*(?P<next_hop>\S+)", block, re.I)
            interface_match = re.search(r"(?:Interface|Output interface)\s*:\s*(?P<interface>\S+)", block, re.I)
            age_match = re.search(r"Age\s*:\s*(?P<age>\S+)", block, re.I)

            if (
                destination_match is None
                or protocol_match is None
                or preference_match is None
                or cost_match is None
                or next_hop_match is None
                or interface_match is None
            ):
                continue
            route_protocol = protocol_match.group("protocol")
            if protocol_filter and route_protocol.lower() != protocol_filter:
                continue

            prefix = destination_match.group("prefix")
            route = {
                "protocol": route_protocol.upper(),
                "current_active": True,
                "last_active": False,
                "age": parse_time(age_match.group("age")) if age_match else 0,
                "next_hop": next_hop_match.group("next_hop"),
                "outgoing_interface": _normalize_outgoing_interface(interface_match.group("interface")),
                "selected_next_hop": True,
                "preference": int(preference_match.group("preference")),
                "inactive_reason": "",
                "routing_table": routing_table,
                "protocol_attributes": {"metric": int(cost_match.group("cost"))},
            }
            routes.setdefault(prefix, []).append(route)

        return routes

    def _get_structured_output(self, command: str, template_name: Optional[str] = None) -> StructuredOutput:
        if template_name is None:
            template_name = "_".join(command.split())
        raw_output = self.send_command(command)
        return cast(StructuredOutput, cast(Any, napalm_helpers).textfsm_extractor(self, template_name, raw_output))

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

        try:
            version = cast(Dict[str, Any], self._get_version()) or {}
            hostname = self.find_prompt()[1:-1]
            manuinfo = self._get_device_manuinfo() or []
            interfaces = self.get_interfaces() or {}
        except Exception as e:
            raise ValueError(f"Data collection failed: {str(e)}") from e

        serials: List[str] = []
        for item in manuinfo:
            serial_number = item.get("serial_number")
            if serial_number:
                sn = str(serial_number).strip()
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

        logger.debug(f"Structured version info: {structured_output}")

        if len(structured_output) != 1:
            logger.error(f"Unexpected version output format: {structured_output}")
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
            logger.error(f"Failed to parse version info: {str(e)}")
            return None

    def _get_device_manuinfo(self) -> List[DeviceManuinfoItem]:
        cmd = "display device manuinfo"
        structured_output = self._get_structured_output(cmd)
        result: List[DeviceManuinfoItem] = []
        for item in structured_output:
            normalized: DeviceManuinfoItem = {
                "chassis_id": item.get("chassis_id", ""),
                "slot_type": cast(Literal["Slot", "Fan", "Power"], item["slot_type"]),
                "slot_id": str(item["slot_id"]),
                "device_name": str(item["device_name"]) if item.get("device_name") else None,
                "serial_number": SerialNumber(str(item["serial_number"])) if item.get("serial_number") else None,
                "manufacturing_date": str(item["manufacturing_date"]) if item.get("manufacturing_date") else None,
                "vendor_name": str(item["vendor_name"]) if item.get("vendor_name") else None,
                "mac_address": MACAddress(str(item["mac_address"])) if item.get("mac_address") else None,
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
                interface_name = str(interface.get("interface", ""))
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
                logger.warning(f"Error processing interface {interface.get('interface')}: {e}")
                continue

        return interface_dict

    def get_interfaces_counters(self) -> Dict[str, models.InterfaceCounterDict]:
        output = self.send_command("display interface")
        sections = self._separate_section(r"(^\S+.*current state.*$)", output)
        counters: Dict[str, models.InterfaceCounterDict] = {}

        for section in sections:
            match_intf = re.search(r"^(?P<intf_name>\S+).+current state\W+(?P<intf_state>.+)$", section, flags=re.M)
            if match_intf is None:
                continue

            intf_name = canonical_interface_name_comware(match_intf.group("intf_name"))
            match_errors = re.findall(r"Total Error:\s+(\d+)|(\d+)\s+errors", section, flags=re.M)
            match_unicast = re.findall(r"Unicast:\s+(\d+)|(\d+)\s+unicast", section, flags=re.M)
            match_multicast = re.findall(r"Multicast:\s+(\d+)|(\d+)\s+multicast", section, flags=re.M)
            match_broadcast = re.findall(r"Broadcast:\s+(\d+)|(\d+)\s+broadcast", section, flags=re.M)
            match_discards = re.findall(r"Discard:\s+(\d+)|(\d+)\s+discard", section, flags=re.M)
            match_rx_octets = re.findall(r"Input.+\s+(\d+)\sbytes|Input:.+,(\d+)\sbytes", section, flags=re.M)
            match_tx_octets = re.findall(r"Output.+\s+(\d+)\sbytes|Output:.+,(\d+)\sbytes", section, flags=re.M)

            counters[intf_name] = {
                "tx_errors": self._process_count_match(match_errors, 1),
                "rx_errors": self._process_count_match(match_errors, 0),
                "tx_discards": self._process_count_match(match_discards, 1),
                "rx_discards": self._process_count_match(match_discards, 0),
                "tx_octets": self._process_count_match(match_tx_octets, 0),
                "rx_octets": self._process_count_match(match_rx_octets, 0),
                "tx_unicast_packets": self._process_count_match(match_unicast, 1),
                "rx_unicast_packets": self._process_count_match(match_unicast, 0),
                "tx_multicast_packets": self._process_count_match(match_multicast, 1),
                "rx_multicast_packets": self._process_count_match(match_multicast, 0),
                "tx_broadcast_packets": self._process_count_match(match_broadcast, 1),
                "rx_broadcast_packets": self._process_count_match(match_broadcast, 0),
            }

        return counters

    def _parse_interface_status(self, interface: Dict[str, str]) -> tuple[bool, bool]:
        link_status = interface.get("link_status", "").lower()
        protocol_status = interface.get("protocol_status", "").lower()
        is_enabled = "administratively" not in link_status
        protocol_status_split = protocol_status.split()
        if len(protocol_status_split) == 0:
            logger.warning(f"cannot get up status for interface: {interface}")
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
            return -1.0
        flapping_str = flapping_str.lower()
        if "never" in flapping_str:
            return -1.0
        try:
            elapsed = parse_time(flapping_str)
            return time.time() - elapsed
        except Exception:
            return -1.0

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

            except (KeyError, TypeError):
                continue
            except Exception as e:
                raise ValueError(f"LLDP data parsing error: {str(e)}") from e

        return lldp_neighbors

    def _get_memory(self, verbose: Literal[True, False] = True) -> Dict[str, MemoryEntry]:
        """Get device memory info (multi-slot support).

        Args:
            verbose: Whether to return detailed per-slot info.

        Returns:
            When verbose=True, returns dict with per-slot details.
            When verbose=False, returns dict with single "summary" key for most utilized slot.

        Raises:
            CommandErrorException: If device command fails.
            ValueError: If data parsing fails.
        """
        memory: Dict[str, MemoryEntry] = {}
        required_fields = ("chassis", "slot", "total", "used", "free", "free_ratio")

        try:
            structured_output = self._get_structured_output("display memory")
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

        return {"summary": most_used[1]}

    def _get_power(self) -> PowerDict:
        """Get device power supply info.

        Returns:
            Dict keyed by slot/power ID, each containing status (bool), capacity (float), and output (str).
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
        """Build key name for power info dict."""
        if slot:
            return f"slot {slot} power {power_id}"
        if chassis:
            return f"chassis {chassis} power {power_id}"
        return f"power {power_id}"

    def _get_cpu(self, verbose: bool = True) -> models.CPUDict:
        """Get device CPU usage info.

        Args:
            verbose: True returns per-core five_sec/one_min/five_min, False returns peak %usage only.
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
            except (ValueError, TypeError):
                continue

            if verbose:
                cpu[cpu_key] = VerboseCpuInfo(five_sec=five_sec_f, one_min=one_min_f, five_min=five_min_f)
            else:
                cpu[cpu_key] = {"%usage": max(five_sec_f, one_min_f, five_min_f)}

        return cpu

    def _build_cpu_key(self, chassis: str, slot: str, cpu_id: str) -> str:
        if chassis:
            return f"chassis {chassis} slot {slot} cpu {cpu_id}"
        elif slot:
            return f"slot {slot} cpu {cpu_id}"
        return f"cpu {cpu_id}"

    def _get_fan(self) -> FanDict:
        """Get device fan status info. Returns dict keyed by slot/fan ID with status bool."""
        fans: FanDict = {}
        command = "display fan"
        structured_output = self._get_structured_output(command)

        for fan_entry in structured_output:
            chassis, slot, fan_id, status = itemgetter("chassis", "slot", "fan_id", "status")(fan_entry)

            fan_key = self._build_fan_key(chassis, slot, fan_id)

            status_bool = status.lower() == "normal"
            fans[fan_key] = models.FanDict(status=status_bool)

        return fans

    def _build_fan_key(self, chassis: str, slot: str, fan_id: str) -> str:
        if slot:
            return f"slot {slot} fan {fan_id}"
        elif chassis:
            return f"chassis {chassis} fan {fan_id}"
        return f"fan {fan_id}"

    def _get_temperature(self) -> TemperatureDict:
        """Get device temperature sensor info. Returns dict with temperature, is_alert, is_critical per sensor."""
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

            temperature[temp_key] = models.TemperatureDict(
                temperature=temp_f, is_alert=temp_f >= alert_f, is_critical=temp_f >= critical_f
            )

        return temperature

    def _build_temp_key(self, chassis: str, slot: str, sensor: str) -> str:
        """Build key name for temperature sensor dict."""
        if chassis:
            return f"chassis {chassis} slot {slot} sensor {sensor}"
        return f"slot {slot} sensor {sensor}"

    def get_environment(self, use_cache: bool = True) -> EnvironmentDict:
        """Get device environment data (CPU, memory, power, fans, temperature) in parallel.

        Args:
            use_cache: Whether to use cached data (default True). Set False to force refresh.

        Returns:
            EnvironmentDict with cpu, memory, power, fans, temperature keys.

        Raises:
            RuntimeError: If any subsystem data collection fails.
        """
        if use_cache and self._is_cache_valid():
            if self._env_cache is None:
                raise RuntimeError("Environment cache is empty but was expected to be populated")
            return self._env_cache

        try:
            with ThreadPoolExecutor(max_workers=5) as executor:
                get_data = partial(self._get_subsystem_data, verbose=False)
                futures = {
                    "cpu": executor.submit(get_data, "_get_cpu"),
                    "memory": executor.submit(get_data, "_get_memory"),
                    "power": executor.submit(self._get_power),
                    "fans": executor.submit(self._get_fan),
                    "temperature": executor.submit(self._get_temperature),
                }

                raw_cpu = futures["cpu"].result()
                raw_memory: Dict[str, MemoryEntry] = futures["memory"].result()
                summary_memory = raw_memory.get(
                    "summary",
                    MemoryEntry(total_ram=0, used_ram=0, available_ram=0, free_ratio=0.0),
                )
                cpu_usage: Dict[int, models.CPUDict] = {}

                for cpu_key, cpu_data in raw_cpu.items():
                    if cpu_key == "%usage" or not isinstance(cpu_data, dict):
                        continue
                    cpu_data_dict = cast(Dict[str, Any], cpu_data)
                    usage = cpu_data_dict.get("%usage")
                    if isinstance(usage, (int, float)):
                        cpu_usage[len(cpu_usage)] = {"%usage": float(usage)}

                environment = EnvironmentDict(
                    cpu=cpu_usage,
                    memory={"available_ram": summary_memory["available_ram"], "used_ram": summary_memory["used_ram"]},
                    power=futures["power"].result(),
                    fans=futures["fans"].result(),
                    temperature=futures["temperature"].result(),
                )
        except Exception as e:
            logger.error(f"Environment data collection failed: {str(e)}")
            raise RuntimeError("Failed to collect environment data") from e

        self._env_cache = environment
        self._last_update_time = time.time()

        return environment

    def _get_subsystem_data(self, method_name: str, **kwargs: Any) -> Dict[str, Any]:
        try:
            method = getattr(self, method_name)
            return cast(Dict[str, Any], method(**kwargs))
        except Exception as e:
            logger.error(f"Failed to get {method_name} data: {str(e)}")
            raise RuntimeError(f"Failed to get {method_name} data") from e

    def _is_cache_valid(self) -> bool:
        return self._env_cache is not None and (time.time() - self._last_update_time) < self._cache_ttl

    def clear_cache(self) -> None:
        self._env_cache = None
        self._last_update_time = 0.0

    def get_lldp_neighbors_detail(self, interface: str = "") -> models.LLDPNeighborsDetailDict:
        lldp: models.LLDPNeighborsDetailDict = {}
        parent_interface = ""

        if interface:
            if not re.match(r"^[a-zA-Z0-9/_-]+$", interface):
                raise ValueError(f"Invalid interface name: {interface}")
            command = f"display lldp neighbor-information interface {interface} verbose"
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
            neighbor_detail: models.LLDPNeighborDetailDict = {
                "parent_interface": parent_interface,
                "remote_port": str(remote_port),
                "remote_port_description": str(remote_port_description),
                "remote_chassis_id": str(remote_chassis_id),
                "remote_system_name": str(remote_system_name),
                "remote_system_description": " ".join(_as_str_list(remote_system_description)).strip(),
                "remote_system_capab": [x.strip() for x in remote_system_capab.split(",") if x.strip()],
                "remote_system_enable_capab": [x.strip() for x in remote_system_enabled_capab.split(",") if x.strip()],
            }
            local_interface_name = str(local_interface)
            if local_interface_name not in lldp:
                lldp[local_interface_name] = [neighbor_detail]
            else:
                lldp[local_interface_name].append(neighbor_detail)
        return lldp

    def cli(self, commands: List[str], encoding: str = "text") -> Dict[str, Union[str, Dict[str, Any]]]:
        cli_output: Dict[str, Union[str, Dict[str, Any]]] = {}

        if encoding != "text":
            raise NotImplementedError(f"Unsupported encoding: {encoding}")
        if not isinstance(commands, list):
            raise TypeError("commands must be provided as a list of strings")
        if not all(isinstance(command, str) for command in commands):
            raise TypeError("commands must contain only strings")

        for command in commands:
            cli_output[command] = self.send_command(command)

        return cli_output

    def get_arp_table(self, vrf: str = "") -> List[ArpEntry]:
        """Get ARP table (supports VRF).

        Args:
            vrf: Optional VRF instance name. Defaults to global routing table.

        Returns:
            List of ArpEntry with interface, mac, ip, age fields.

        Raises:
            CommandErrorException: If CLI command fails.
            ValueError: If VRF name is invalid.
        """
        if vrf and not re.match(r"^[a-zA-Z0-9_.-]+$", vrf):
            raise ValueError(f"Invalid VRF name: {vrf}")
        command = f"display arp vpn-instance {vrf}" if vrf else "display arp"
        try:
            structured_output: List[Dict[str, str]] = self._get_structured_output(command, template_name="display_arp")
        except Exception as e:
            raise CommandErrorException(f"ARP command execute error: {command}") from e

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
                logger.warning(f"Skipping invalid ARP entry: {arp_entry}, error: {e}")
                continue

        return arp_table

    def get_ipv6_neighbors_table(self) -> List[models.IPV6NeighborDict]:
        output = self.send_command("display ipv6 neighbors")
        neighbors: List[models.IPV6NeighborDict] = []
        patterns = (
            re.compile(r"^(?P<ip>[0-9a-fA-F:]+)\s+(?P<mac>[0-9A-Fa-f-]+)\s+(?P<state>\S+)\s+(?P<interface>\S+)$"),
            re.compile(
                r"^(?P<ip>[0-9a-fA-F:]+)\s+(?P<mac>[0-9A-Fa-f-]+)\s+(?P<age>\d+)\s+(?P<state>\S+)\s+(?P<interface>\S+)$"
            ),
        )

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.lower().startswith(("ipv6 address", "<")):
                continue

            match = None
            for pattern in patterns:
                match = pattern.match(stripped)
                if match:
                    break
            if match is None:
                continue

            neighbors.append(
                {
                    "interface": canonical_interface_name_comware(match.group("interface")),
                    "mac": mac(match.group("mac")),
                    "ip": match.group("ip"),
                    "age": float(match.groupdict().get("age", -1) or -1),
                    "state": match.group("state"),
                }
            )

        return neighbors

    def get_interfaces_ip(self) -> Dict[str, models.InterfacesIPDict]:
        interfaces: Dict[str, models.InterfacesIPDict] = {}
        command = "display ip interface"

        try:
            structured_output = self._get_structured_output(command)
        except Exception as e:
            raise CommandErrorException(f"Failed to execute '{command}': {str(e)}") from e

        for iface_entry in structured_output:
            try:
                interface = str(iface_entry["interface"])
                ip_list_raw = iface_entry["ip_address"]
                ip_list = _as_str_list(ip_list_raw)

                if not ip_list:
                    continue

                ipv4: Dict[str, models.InterfacesIPDictEntry] = {}
                for ip_entry in ip_list:
                    try:
                        ip, prefix = ip_entry.split("/")
                        ipv4[ip] = {"prefix_length": int(prefix)}
                    except (ValueError, IndexError):
                        continue

                if ipv4:
                    interfaces[interface] = {"ipv4": ipv4}

            except KeyError:
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
            raise CommandErrorException(f"Failed to execute '{command}': {str(e)}") from e

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
                    "mac": mac(str(mac_address)),
                    "vlan": int(vlan),
                    "current_port": canonical_interface_name_comware(current_port),
                    "source_port": canonical_interface_name_comware(source_port),
                    "last_move": last_move.strip(),
                    "moves": int(moves),
                }
                mac_address_move_table.append(entry)

            except (KeyError, ValueError, AttributeError) as e:
                logger.warning(f"error when execute command: {command},error: {e}")
                continue

        return mac_address_move_table

    def get_mac_address_table(self, move_table: Optional[List[MacMoveEntry]] = None) -> List[models.MACAdressTable]:
        command = "display mac-address"
        structured_output = self._get_structured_output(command)

        if move_table is not None:
            move_by_mac = {(entry["mac"], entry["vlan"]): entry for entry in move_table}
        else:
            move_by_mac = {}

        mac_address_table: List[models.MACAdressTable] = []
        for mac_entry in structured_output:
            (mac_address, vlan, state, interface) = itemgetter("mac_address", "vlan", "state", "interface")(mac_entry)
            normalized_mac = mac(mac_address)
            move_info = move_by_mac.get((normalized_mac, int(vlan)))
            entry: models.MACAdressTable = {
                "mac": normalized_mac,
                "interface": canonical_interface_name_comware(interface),
                "vlan": int(vlan),
                "static": "tatic" in state.lower(),
                "active": True,
                "last_move": strptime(move_info["last_move"]) if move_info else -1.0,
                "moves": int(move_info["moves"]) if move_info else -1,
            }
            mac_address_table.append(entry)

        return mac_address_table

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """Get device configuration.

        Args:
            retrieve: Config type - "all", "running", "startup", or "candidate" (not yet supported).
            full: Full config retrieval (not yet implemented).
            sanitized: Sanitize sensitive info (not yet implemented).
            format: "text" or "json" (json not yet implemented).

        Returns:
            Dict with startup, running, candidate keys.

        Raises:
            ValueError: If invalid retrieve value or format.
        """
        if retrieve.lower() not in ("all", "running", "startup", "candidate"):
            raise ValueError(f"Invalid retrieve value: {retrieve}. Must be one of: all, running, startup, candidate")

        if format.lower() not in ("text", "json"):
            raise ValueError(f"Unsupported format: {format}. Only 'text' or 'json' are supported")

        configs: models.ConfigDict = {"startup": "", "running": "", "candidate": ""}

        try:
            if retrieve.lower() in ("running", "all"):
                command = "display current-configuration"
                configs["running"] = self.send_command(command)

            if retrieve.lower() in ("startup", "all"):
                command = "display saved-configuration"
                configs["startup"] = self.send_command(command)

            if retrieve.lower() in ("candidate", "all"):
                configs["candidate"] = self._candidate_config

            # TODO: implement full config retrieval
            if full:
                raise NotImplementedError("Full config retrieval is not yet implemented")

            # TODO: implement config sanitization
            if sanitized:
                raise NotImplementedError("Config sanitization is not yet implemented")

            # TODO: implement output format conversion
            if format.lower() == "json":
                raise NotImplementedError("JSON format is not yet implemented")

        except Exception as e:
            logger.error(f"Failed to retrieve config: {str(e)}")
            raise

        return configs

    def load_merge_candidate(self, filename: Optional[str] = None, config: Optional[str] = None) -> None:
        self._candidate_config = self._load_candidate_config(
            filename=filename,
            config=config,
            exception_cls=MergeConfigException,
        )
        self._replace_candidate = False

    def load_replace_candidate(self, filename: Optional[str] = None, config: Optional[str] = None) -> None:
        self._candidate_config = self._load_candidate_config(
            filename=filename,
            config=config,
            exception_cls=ReplaceConfigException,
        )
        self._replace_candidate = True

    def compare_config(self) -> str:
        if not self._candidate_config.strip():
            return ""

        running_config = self.get_config(retrieve="running")["running"]
        running_lines = set(running_config.splitlines())

        if self._replace_candidate:
            diff = difflib.unified_diff(
                running_config.splitlines(),
                self._candidate_config.splitlines(),
                fromfile="running-config",
                tofile="candidate-config",
                lineterm="",
            )
            return "\n".join(diff)

        added_lines = [
            line
            for line in self._candidate_config.splitlines()
            if line.strip() and line.strip() not in ("#", "return") and line not in running_lines
        ]
        if not added_lines:
            return "No changes to commit."
        return "The following lines will be added:\n" + "\n".join(added_lines)

    def discard_config(self) -> None:
        self._candidate_config = ""
        self._replace_candidate = False
        self._running_config_lines = None
        self._running_config_text = None

    def commit_config(self, message: str = "", revert_in: Optional[int] = None) -> None:
        if message:
            raise NotImplementedError("Comware does not support commit messages")
        if revert_in is not None:
            raise NotImplementedError("Comware does not support commit confirm/revert timers")
        if not self._candidate_config.strip():
            return
        if self._replace_candidate:
            raise ReplaceConfigException("Comware replace commit is not yet supported")

        commands = [
            line.strip()
            for line in self._candidate_config.splitlines()
            if line.strip() and line.strip() not in ("#", "return")
        ]
        if not commands:
            self.discard_config()
            return

        backup_file = self._BACKUP_CONFIG_FILES[1] if self._replace_candidate else self._BACKUP_CONFIG_FILES[0]
        try:
            backup_output = self.send_command(f"save force {backup_file} safely")
            if _has_cli_error(backup_output):
                logger.warning(f"Failed to save pre-commit backup to {backup_file}: {backup_output.strip()}")
            else:
                self._last_backup_file = backup_file
        except Exception:
            logger.warning(f"Failed to save pre-commit backup to {backup_file}, proceeding anyway")

        try:
            self.send_config_set(commands)
            self.send_command("save force")
        except Exception as exc:
            self._running_config_lines = None
            self._running_config_text = None
            raise CommitError("Failed to commit candidate config on Comware") from exc

        self._running_config_lines = None
        self._running_config_text = None
        self.discard_config()

    def rollback(self) -> None:
        if self.device is None:
            raise ReplaceConfigException("Rollback failed: device is not connected")
        backup_files = self._get_backup_files_for_rollback()

        for backup_file in backup_files:
            for command in (
                f"rollback configuration to file {backup_file}",
                f"configuration replace file flash:/{backup_file}",
            ):
                try:
                    rollback_output = self.send_command(command)
                except Exception:
                    continue
                if _has_cli_error(rollback_output):
                    continue

                save_output = self.send_command("save force")
                if _has_cli_error(save_output):
                    raise ReplaceConfigException("Rollback restored config but failed to save it")

                self._last_backup_file = backup_file
                self._running_config_lines = None
                self._running_config_text = None
                self.discard_config()
                return
        raise ReplaceConfigException("Rollback failed: no backup config found on flash")

    def _get_backup_files_for_rollback(self) -> List[str]:
        directory_output = ""
        for command in ("dir flash:", "display directory flash:"):
            try:
                response = self.send_command(command)
            except Exception:
                continue
            if _has_cli_error(response):
                continue
            directory_output = response
            break

        if directory_output:
            timestamps = _parse_directory_timestamps(directory_output, list(self._BACKUP_CONFIG_FILES))
            if timestamps:
                ranked_files = sorted(
                    self._BACKUP_CONFIG_FILES,
                    key=lambda file: (
                        timestamps.get(file, -1),
                        1 if file == self._last_backup_file else 0,
                    ),
                    reverse=True,
                )
                return list(ranked_files)

        backup_files: List[str] = []
        if self._last_backup_file:
            backup_files.append(self._last_backup_file)
        backup_files.extend(file for file in self._BACKUP_CONFIG_FILES if file not in backup_files)
        return backup_files

    def get_ntp_peers(self) -> Dict[str, models.NTPPeerDict]:
        ntp_peers: Dict[str, models.NTPPeerDict] = {}
        for line in self._get_running_config_lines():
            match = re.match(r"^ntp-service peer (?P<peer>\S+)", line)
            if match:
                ntp_peers[match.group("peer")] = {}
        return ntp_peers

    def get_ntp_servers(self) -> Dict[str, models.NTPServerDict]:
        ntp_servers: Dict[str, models.NTPServerDict] = {}
        server_patterns = (
            r"^ntp-service server (?P<server>\S+)",
            r"^ntp-service unicast-server (?P<server>\S+)",
            r"^ntp-service multicast-server (?P<server>\S+)",
            r"^ntp-service broadcast-server (?P<server>\S+)",
        )
        for line in self._get_running_config_lines():
            for pattern in server_patterns:
                match = re.match(pattern, line)
                if match:
                    ntp_servers[match.group("server")] = {}
                    break
        return ntp_servers

    def get_ntp_stats(self) -> List[models.NTPStats]:
        output = self.send_command("display ntp sessions")
        ntp_stats: List[models.NTPStats] = []

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("address", "=", "<")):
                continue

            match = re.match(
                r"^(?P<flag>[\*\+\-x#~o ]?)\s*(?P<remote>\S+)\s+(?P<refid>\S+)\s+"
                r"(?P<stratum>\d+)\s+(?P<assoc_type>\S+)\s+(?P<when>\S+)\s+"
                r"(?P<poll>\d+)\s+(?P<reach>\d+)\s+(?P<delay>[\d.]+)\s+"
                r"(?P<offset>[-\d.]+)\s+(?P<disp>[\d.]+)$",
                stripped,
            )
            if match is None:
                continue

            ntp_stats.append(
                {
                    "remote": match.group("remote"),
                    "referenceid": match.group("refid"),
                    "synchronized": match.group("flag") == "*",
                    "stratum": int(match.group("stratum")),
                    "type": match.group("assoc_type"),
                    "when": match.group("when"),
                    "hostpoll": int(match.group("poll")),
                    "reachability": int(match.group("reach")),
                    "delay": float(match.group("delay")),
                    "offset": float(match.group("offset")),
                    "jitter": float(match.group("disp")),
                }
            )

        if ntp_stats:
            return ntp_stats

        output = self.send_command("display ntp status")
        sync_match = re.search(r"Clock?\s+status:\s+(?P<status>\S+)", output, re.I)
        stratum_match = re.search(r"Clock?\s+stratum:\s+(?P<stratum>\d+)", output, re.I)
        refid_match = re.search(r"Reference clock ID:\s+(?P<refid>\S+)", output, re.I)
        if sync_match and stratum_match and refid_match:
            return [
                {
                    "remote": refid_match.group("refid"),
                    "referenceid": refid_match.group("refid"),
                    "synchronized": sync_match.group("status").lower() == "synchronized",
                    "stratum": int(stratum_match.group("stratum")),
                    "type": "-",
                    "when": "",
                    "hostpoll": 0,
                    "reachability": 0,
                    "delay": 0.0,
                    "offset": 0.0,
                    "jitter": 0.0,
                }
            ]

        return []

    def get_snmp_information(self) -> models.SNMPDict:
        communities: Dict[str, models.SNMPCommunityDict] = {}
        contact = ""
        location = ""

        for line in self._get_running_config_lines():
            community_match = re.match(
                r"^snmp-agent community (?P<mode>read|write) "
                r"(?:(?:cipher|simple)\s+)?(?P<name>\S+)(?: acl (?P<acl>\S+))?",
                line,
            )
            if community_match:
                mode = "ro" if community_match.group("mode") == "read" else "rw"
                communities[community_match.group("name")] = {
                    "mode": mode,
                    "acl": community_match.group("acl") or "",
                }
                continue

            contact_match = re.match(r"^snmp-agent sys-info contact (?P<contact>.+)$", line)
            if contact_match:
                contact = contact_match.group("contact").strip()
                continue

            location_match = re.match(r"^snmp-agent sys-info location (?P<location>.+)$", line)
            if location_match:
                location = location_match.group("location").strip()

        facts = self.get_facts()
        chassis_id = facts["serial_number"] if "serial_number" in facts else ""
        return {
            "chassis_id": chassis_id,
            "community": communities,
            "contact": contact,
            "location": location,
        }

    def get_network_instances(self, name: str = "") -> Dict[str, models.NetworkInstanceDict]:
        network_instances: Dict[str, models.NetworkInstanceDict] = {
            "default": {
                "name": "default",
                "type": "DEFAULT_INSTANCE",
                "state": {"route_distinguisher": ""},
                "interfaces": {"interface": {}},
            }
        }
        interface_bindings: Dict[str, str] = {}
        current_instance: Optional[str] = None
        current_interface: Optional[str] = None

        for raw_line in self.get_config(retrieve="running")["running"].splitlines():
            line = raw_line.rstrip()
            stripped = line.strip()
            if not stripped:
                continue

            if not raw_line.startswith(" "):
                current_instance = None
                current_interface = None

                if stripped.startswith("ip vpn-instance "):
                    current_instance = stripped.split(maxsplit=2)[2]
                    network_instances.setdefault(
                        current_instance,
                        {
                            "name": current_instance,
                            "type": "L3VRF",
                            "state": {"route_distinguisher": ""},
                            "interfaces": {"interface": {}},
                        },
                    )
                    continue

                if stripped.startswith("interface "):
                    current_interface = canonical_interface_name_comware(stripped.split(maxsplit=1)[1])
                    interface_bindings.setdefault(current_interface, "default")
                    continue

            if current_instance and stripped.startswith("route-distinguisher "):
                network_instances[current_instance]["state"]["route_distinguisher"] = stripped.split(maxsplit=1)[1]
                continue

            if current_interface:
                vrf_match = re.match(r"^(?:ip binding )?vpn-instance (?P<vrf>\S+)$", stripped)
                if vrf_match:
                    vrf_name = vrf_match.group("vrf")
                    interface_bindings[current_interface] = vrf_name
                    network_instances.setdefault(
                        vrf_name,
                        {
                            "name": vrf_name,
                            "type": "L3VRF",
                            "state": {"route_distinguisher": ""},
                            "interfaces": {"interface": {}},
                        },
                    )

        for interface_name, vrf_name in interface_bindings.items():
            network_instances.setdefault(
                vrf_name,
                {
                    "name": vrf_name,
                    "type": "L3VRF",
                    "state": {"route_distinguisher": ""},
                    "interfaces": {"interface": {}},
                },
            )
            network_instances[vrf_name]["interfaces"]["interface"][interface_name] = {}

        if name:
            return {name: network_instances[name]} if name in network_instances else {}
        return network_instances

    def _load_candidate_config(
        self,
        filename: Optional[str] = None,
        config: Optional[str] = None,
        exception_cls: Type[Exception] = MergeConfigException,
    ) -> str:
        if filename:
            try:
                return Path(filename).read_text()
            except OSError as exc:
                raise exception_cls(f"Unable to read candidate config file: {filename}") from exc

        if config is None:
            raise exception_cls("filename or config must be provided")

        return config

    def _get_running_config_lines(self) -> List[str]:
        if self._running_config_lines is None:
            raw = self.get_config(retrieve="running")["running"]
            self._running_config_text = raw
            self._running_config_lines = [line.strip() for line in raw.splitlines() if line.strip()]
        return self._running_config_lines

    @staticmethod
    def _separate_section(separator: str, content: str) -> List[str]:
        if content == "":
            return []

        sections = re.split(separator, content, flags=re.M)
        if len(sections) == 1:
            return [content]

        sections.pop(0)
        if len(sections) % 2 != 0:
            raise ValueError(f"Unexpected output data:\n{content}")

        section_iter = iter(sections)
        return [header + next(section_iter, "") for header in section_iter]

    @staticmethod
    def _process_count_match(matches: List[tuple[str, ...]], index: int) -> int:
        for match in matches:
            if index < len(match) and match[index]:
                return int(match[index])
        return 0

    @staticmethod
    def _map_user_level(value: str) -> int:
        normalized = value.strip().lower()
        if normalized in {"manage", "system", "network-admin"}:
            return 15
        if normalized in {"monitor", "network-operator"}:
            return 5
        if normalized in {"visit", "network-monitor"}:
            return 1
        return 0

    def get_users(self) -> Dict[str, models.UsersDict]:
        users: Dict[str, models.UsersDict] = {}
        self._get_running_config_lines()
        config = self._running_config_text or ""
        blocks = re.split(r"(?m)^\s*#\s*$", config)

        for block in blocks:
            lines = [line.rstrip() for line in block.splitlines() if line.strip()]
            if not lines:
                continue

            header = lines[0].strip()
            header_match = re.match(r"^local-user\s+(?P<username>\S+)(?:\s+class\s+(?P<user_class>\S+))?$", header)
            if header_match is None:
                continue

            username = header_match.group("username")
            user: models.UsersDict = {
                "level": self._map_user_level(header_match.group("user_class") or ""),
                "password": "",
                "sshkeys": [],
            }

            for raw_line in lines[1:]:
                line = raw_line.strip()

                password_match = re.match(
                    r"^password\s+(?:cipher|simple|irreversible-cipher)\s+(?P<password>.+)$",
                    line,
                )
                if password_match:
                    user["password"] = password_match.group("password").strip()
                    continue

                role_match = re.match(r"^authorization-attribute\s+user-role\s+(?P<role>\S+)$", line)
                if role_match:
                    user["level"] = max(user["level"], self._map_user_level(role_match.group("role")))

            users[username] = user

        return users

    def get_vlans(self) -> Dict[str, models.VlanDict]:
        """Get device VLAN info.

        Returns:
            Dict keyed by VLAN ID, each with name (str) and interfaces (List[str]).

        Raises:
            CommandErrorException: If VLAN command fails.
            ValueError: If data parsing fails.
        """
        command = "display vlan all"
        try:
            structured_output: List[Dict[str, Union[str, List[str]]]] = self._get_structured_output(command)
        except Exception as e:
            raise CommandErrorException(f"VLAN command execute failed: {command}") from e

        vlans: Dict[str, models.VlanDict] = {}
        required_fields = ("vlan_id", "name", "description", "interfaces")
        get_fields = itemgetter(*required_fields)

        for vlan_entry in structured_output:
            try:
                vlan_id, name, desc, interfaces = get_fields(vlan_entry)
                vlan_id_str = str(vlan_id)
                name_str = str(name)
                desc_str = str(desc)
                interface_list = _as_str_list(interfaces) if isinstance(interfaces, list) else []
                final_name = (
                    desc_str
                    if not desc_str.startswith(self._DEFAULT_VLAN_PREFIX)
                    and name_str.startswith(self._DEFAULT_VLAN_PREFIX)
                    else name_str
                )

                vlans[vlan_id_str] = {
                    "name": final_name.strip(),
                    "interfaces": [canonical_interface_name_comware(str(iface)) for iface in interface_list if iface],
                }
            except (KeyError, ValueError, AttributeError) as e:
                raise ValueError(f"invalid vlan item: {vlan_entry}") from e

        return vlans

    def get_irf_config(self) -> IrfConfigDict:
        command = "display current-configuration configuration irf-port"
        try:
            structured_output = self._get_structured_output(command)
        except Exception as e:
            raise CommandErrorException(f"IRF config command failed: {command}") from e

        temp_config: Dict[int, Dict[str, List[str]]] = defaultdict(lambda: {"irf-port1": [], "irf-port2": []})

        for config in structured_output:
            try:
                member_id = int(config["member_id"])
                port_id = str(config["port_id"])
                port_member = _as_str_list(config.get("port_member"))
                port_key = f"irf-port{port_id}"

                if port_key not in ("irf-port1", "irf-port2"):
                    continue

                temp_config[member_id][port_key] = [self._normalize_interface(iface) for iface in port_member if iface]
            except (KeyError, ValueError) as e:
                raise ValueError(f"Invalid IRF config entry: {config}") from e

        final_config = {
            member_id: cast(IrfPortConfig, {"irf_port1": ports["irf-port1"], "irf_port2": ports["irf-port2"]})
            for member_id, ports in temp_config.items()
        }
        return final_config

    def _normalize_interface(self, interface: str) -> str:
        return interface.strip().replace(" ", "")

    def is_irf(self) -> bool:
        config = self.get_irf_config()
        return bool(config)
