from typing import (
    Dict,
    Literal,
    NewType,
    Optional,
    TypeAlias,
    TypedDict,
    Union,
)

from napalm.base import models

VersionInfo: TypeAlias = Dict[str, Union[str, int]]

MACAddress = NewType("MACAddress", str)
SerialNumber = NewType("SerialNumber", str)


PowerDict = Dict[str, models.PowerDict]


class VerboseCpuInfo(TypedDict):
    five_sec: float
    one_min: float
    five_min: float


CpuInfo = Union[VerboseCpuInfo, models.CPUDict]
CpuDict = Dict[str, CpuInfo]


class FanInfo(TypedDict):
    status: bool


FanDict = Dict[str, FanInfo]


class MemoryEntry(TypedDict):
    total_ram: int
    used_ram: int
    available_ram: int
    free_ratio: float


class CompactMemory(TypedDict):
    used_ram: int
    available_ram: int


MemoryResult = Union[Dict[str, MemoryEntry], CompactMemory]


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


class TemperatureInfo(TypedDict):
    temperature: float
    is_alert: bool
    is_critical: bool


TemperatureDict = Dict[str, TemperatureInfo]


EnvironmentDict = TypedDict(
    "EnvironmentDict",
    {
        "fans": FanDict,
        "temperature": TemperatureDict,
        "power": PowerDict,
        "cpu": CpuDict,
        "memory": MemoryResult,
    },
)


class ArpEntry(TypedDict):
    interface: str
    mac: str
    ip: str
    age: float
