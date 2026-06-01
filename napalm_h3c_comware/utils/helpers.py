import re
import time
from typing import Any, Callable, List, Optional, TypeVar

from napalm.base.helpers import canonical_interface_name

SECONDS = 60
HOUR_SECONDS = 3600
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS

_COMPACT_UNITS = {
    "y": YEAR_SECONDS,
    "w": WEEK_SECONDS,
    "d": DAY_SECONDS,
    "h": HOUR_SECONDS,
    "m": SECONDS,
    "s": 1,
}


comware_interfaces = {
    "XGE": "Ten-GigabitEthernet",
    "MGE": "M-GigabitEthernet",
    "Vlan": "Vlan-interface",
    "BAGG": "Bridge-Aggregation",
    "RAGG": "Route-Aggregation",
    "Loop": "LoopBack",
    "FGE": "FortyGigE",
    "Ser": "Serial",
    "Dia": "Dialer",
    "Reth": "Reth",
    "Vsi": "Vsi-interface",
    "WGE": "Twenty-FiveGigE",
}


def canonical_interface_name_comware(interface: str) -> str:
    return str(
        canonical_interface_name(
            interface=interface,
            addl_name_map=comware_interfaces,
        )
    )


def _search(unit: str, time_str: str) -> int:
    pattern = rf"(\d+)\s*{unit}(?:s)?\b"
    match = re.search(pattern, time_str, re.IGNORECASE)
    return int(match.group(1)) if match else 0


def parse_time(time_str: str) -> int:
    normalized = time_str.strip().lower()
    if not normalized or normalized in {"--", "never", "none"}:
        return 0

    if re.fullmatch(r"\d+:\d{2}:\d{2}", normalized):
        hours, minutes, seconds = (int(part) for part in normalized.split(":"))
        return (hours * 3600) + (minutes * 60) + seconds
    if re.fullmatch(r"\d+:\d{2}", normalized):
        minutes, seconds = (int(part) for part in normalized.split(":"))
        return (minutes * 60) + seconds
    if normalized.isdigit():
        return int(normalized)

    compact = re.findall(r"(\d+)\s*([ywdhms])", normalized)
    if compact:
        return sum(int(amount) * _COMPACT_UNITS[unit] for amount, unit in compact)

    units = ["year", "week", "day", "hour", "minute", "second"]
    (years, weeks, days, hours, minutes, seconds) = (_search(unit, normalized) for unit in units)
    return (
        (years * YEAR_SECONDS)
        + (weeks * WEEK_SECONDS)
        + (days * DAY_SECONDS)
        + (hours * HOUR_SECONDS)
        + (minutes * SECONDS)
        + seconds
    )


def parse_null(value: Any, default: Any, func: Optional[Callable[..., Any]] = None, *args: Any, **kwargs: Any) -> Any:
    if value == "":
        return default
    if func:
        return func(value, *args, **kwargs)
    return value


def strptime(time_str: str) -> float:
    time_array = time.strptime(time_str, "%Y-%m-%d %H:%M:%S")
    timestamp = time.mktime(time_array)
    return float(timestamp)


T = TypeVar("T")


def get_value_from_list_of_dict(_list: List[dict], dict_key: str, func_max_or_min: Callable[..., T]) -> dict:
    all_item = []
    for _dict in _list:
        all_item.append(_dict.get(dict_key))
    return _list[all_item.index(func_max_or_min(all_item))]
