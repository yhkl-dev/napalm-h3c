from typing import (
    Dict,
    List,
    Literal,
    NewType,
    Optional,
    TypedDict,
    Union,
)

from napalm.base import models


class VersionInfo(TypedDict):
    os_version: str
    vendor: str
    uptime: int
    model: str


MACAddress = NewType("MACAddress", str)
SerialNumber = NewType("SerialNumber", str)


PowerDict = Dict[str, models.PowerDict]


class VerboseCpuInfo(TypedDict):
    five_sec: float
    one_min: float
    five_min: float


CpuInfo = Union[VerboseCpuInfo, models.CPUDict]
CpuDict = Dict[str, CpuInfo]


FanDict = Dict[str, models.FanDict]


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


TemperatureDict = Dict[str, models.TemperatureDict]


class EnvironmentDict(TypedDict):
    fans: FanDict
    temperature: TemperatureDict
    power: PowerDict
    cpu: Dict[int, models.CPUDict]
    memory: models.MemoryDict


class ArpEntry(TypedDict):
    interface: str
    mac: str
    ip: str
    age: float


class VlanInfo(TypedDict):
    name: str
    interfaces: List[str]


VlansDict = Dict[str, VlanInfo]


class IrfPortConfig(TypedDict):
    irf_port1: List[str]
    irf_port2: List[str]


IrfConfigDict = Dict[int, IrfPortConfig]
