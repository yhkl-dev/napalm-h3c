import re
import time

from napalm.base.helpers import canonical_interface_name

SECONDS = 60
HOUR_SECONDS = 3600
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS


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


def canonical_interface_name_comware(interface):
    return canonical_interface_name(
        interface=interface,
        addl_name_map=comware_interfaces,
    )


def _search(unit: str, time_str: str) -> int:
    pattern = rf"(\d+)\s*{unit}(?:s)?\b"
    match = re.search(pattern, time_str, re.IGNORECASE)
    return int(match.group(1)) if match else 0


def parse_time(time_str: str) -> int:
    units = ["year", "week", "day", "hour", "minute", "second"]

    (years, weeks, days, hours, minutes, seconds) = (_search(unit, time_str) for unit in units)
    time_sec = (
        (years * YEAR_SECONDS)
        + (weeks * WEEK_SECONDS)
        + (days * DAY_SECONDS)
        + (hours * HOUR_SECONDS)
        + (minutes * SECONDS)
        + seconds
    )
    return time_sec


def parse_null(value, default, func=None, *args, **kwargs):
    if value == "":
        return default
    if func:
        return func(value, *args, **kwargs)
    return value


def strptime(time_str):
    timeArray = time.strptime(time_str, "%Y-%m-%d %H:%M:%S")
    timestamp = time.mktime(timeArray)
    return timestamp


def get_value_from_list_of_dict(_list, dict_key, func_max_or_min):
    all_item = []
    for _dict in _list:
        all_item.append(_dict.get(dict_key))
    return _list[all_item.index(func_max_or_min(all_item))]
