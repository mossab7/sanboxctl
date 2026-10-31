"""Versioned, compatible synthetic desktop hardware catalog.

The source catalog describes documented *platform families*. At load time a
family expands only across its declared firmware, memory and storage options.
This provides many usable configurations without claiming every combination
was sold as a separate retail SKU.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import secrets
from typing import Any


HARDWARE_CLASSES = ("laptop", "desktop", "gaming-desktop", "workstation", "random")
CATALOG_SCHEMA_VERSION = 1
CATALOG_PATH = Path(__file__).resolve().parents[1] / "catalog" / "hardware_templates.json"
MIN_SYNTHETIC_DISK_MB = 128_000
MAX_SYNTHETIC_DISK_MB = 1_048_576


@dataclass(frozen=True)
class HardwareProfile:
    """One complete synthetic platform identity, persisted per instance."""

    catalog_id: str
    catalog_schema_version: int
    evidence_url: str
    hardware_class: str
    platform: str
    cpu_vendor: str
    cpu_model: str
    cpu_family: int
    cpu_model_id: int
    cpu_stepping: int
    physical_cores: int
    logical_cpus: int
    cpu_mhz: int
    cache_kb: int
    socket: str
    chipset: str
    ram_mb: int
    gpu: str
    motherboard: str
    bios_vendor: str
    bios_version: str
    bios_date: str
    disk_model: str
    disk_size_mb: int
    disk_serial: str
    system_serial: str
    board_serial: str
    chassis_serial: str
    network_adapter: str
    mac: str
    hostname: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HardwareProfile":
        try:
            value = cls(**data)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid persisted hardware profile") from exc
        validate_hardware(value)
        return value


@dataclass(frozen=True)
class CatalogConfiguration:
    """A compatible configuration expanded from one platform family."""

    catalog_id: str
    evidence_url: str
    hardware_class: str
    platform: str
    cpu_vendor: str
    cpu_model: str
    cpu_family: int
    cpu_model_id: int
    cpu_stepping: int
    physical_cores: int
    logical_cpus: int
    cpu_mhz: int
    cache_kb: int
    socket: str
    chipset: str
    ram_mb: int
    gpu: str
    motherboard: str
    bios_vendor: str
    bios_version: str
    bios_date: str
    disk_model: str
    disk_size_mb: int
    network_adapter: str


def _require(raw: dict[str, Any], key: str, type_: type) -> Any:
    value = raw.get(key)
    if not isinstance(value, type_):
        raise ValueError(f"hardware catalog entry is missing valid {key}")
    return value


def load_catalog(path: Path = CATALOG_PATH) -> tuple[CatalogConfiguration, ...]:
    """Load documented platform families and expand them into >=300 variants."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"cannot load hardware catalog: {path}") from exc
    if raw.get("schema_version") != CATALOG_SCHEMA_VERSION:
        raise RuntimeError("unsupported hardware catalog schema")
    templates = raw.get("templates")
    if not isinstance(templates, list) or not templates:
        raise RuntimeError("hardware catalog contains no platform templates")

    expanded: list[CatalogConfiguration] = []
    identifiers: set[str] = set()
    for template in templates:
        if not isinstance(template, dict):
            raise RuntimeError("hardware catalog template must be an object")
        identifier = _require(template, "id", str)
        if identifier in identifiers or not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", identifier):
            raise RuntimeError("hardware catalog identifiers must be unique slugs")
        identifiers.add(identifier)
        hardware_class = _require(template, "class", str)
        if hardware_class not in HARDWARE_CLASSES[:-1]:
            raise RuntimeError(f"unsupported catalog hardware class: {hardware_class}")
        disks = _require(template, "disks", list)
        bios_versions = _require(template, "bios", list)
        ram_options = _require(template, "ram", list)
        if not all(isinstance(item, str) and item for item in bios_versions):
            raise RuntimeError(f"invalid firmware options for {identifier}")
        if not all(isinstance(item, int) and item >= 4096 and item % 1024 == 0 for item in ram_options):
            raise RuntimeError(f"invalid memory options for {identifier}")
        if not all(isinstance(item, list) and len(item) == 2 and isinstance(item[0], str) and isinstance(item[1], int)
                   for item in disks):
            raise RuntimeError(f"invalid disk options for {identifier}")
        fixed = {
            "platform": _require(template, "platform", str),
            "cpu_vendor": _require(template, "cpu_vendor", str),
            "cpu_model": _require(template, "cpu", str),
            "cpu_family": _require(template, "family", int),
            "cpu_model_id": _require(template, "model", int),
            "cpu_stepping": _require(template, "stepping", int),
            "physical_cores": _require(template, "cores", int),
            "logical_cpus": _require(template, "threads", int),
            "cpu_mhz": _require(template, "mhz", int),
            "cache_kb": _require(template, "cache_kb", int),
            "socket": _require(template, "socket", str),
            "chipset": _require(template, "chipset", str),
            "gpu": _require(template, "gpu", str),
            "motherboard": _require(template, "board", str),
            "bios_vendor": _require(template, "bios_vendor", str),
            "bios_date": _require(template, "date", str),
            "network_adapter": _require(template, "nic", str),
            "evidence_url": _require(template, "source", str),
        }
        if fixed["logical_cpus"] < fixed["physical_cores"]:
            raise RuntimeError(f"inconsistent CPU topology in {identifier}")
        for ram_mb in ram_options:
            for disk_model, disk_size_mb in disks:
                if not MIN_SYNTHETIC_DISK_MB <= disk_size_mb <= MAX_SYNTHETIC_DISK_MB:
                    raise RuntimeError(f"unsupported synthetic disk capacity in {identifier}")
                for bios_version in bios_versions:
                    expanded.append(CatalogConfiguration(
                        catalog_id=identifier, hardware_class=hardware_class, ram_mb=ram_mb,
                        disk_model=disk_model, disk_size_mb=disk_size_mb, bios_version=bios_version,
                        **fixed,
                    ))
    if len(expanded) < 300:
        raise RuntimeError("hardware catalog must expand to at least 300 configurations")
    return tuple(expanded)


CATALOG = load_catalog()


def _mac() -> str:
    raw = bytearray(secrets.token_bytes(6))
    raw[0] = (raw[0] & 0xFC) | 0x02
    return ":".join(f"{item:02x}" for item in raw)


def _token(length: int) -> str:
    return "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789") for _ in range(length))


def _manufacturer_serial(vendor: str, kind: str) -> str:
    """Generate OEM-shaped serials without encoding app, profile, or host data."""
    normalized = vendor.upper()
    if "LENOVO" in normalized:
        return f"PF-{_token(8)}"
    if "DELL" in normalized:
        return _token(7)
    if "HP" in normalized:
        return _token(10)
    if "AMERICAN" in normalized or "MSI" in normalized or "ASUS" in normalized:
        return _token(12)
    return _token(10 if kind == "system" else 12)


def _hostname(hardware_class: str) -> str:
    return f"{'LAPTOP' if hardware_class == 'laptop' else 'DESKTOP'}-{_token(7)}"


def validate_hardware(profile: HardwareProfile) -> None:
    if profile.catalog_schema_version != CATALOG_SCHEMA_VERSION:
        raise ValueError("unsupported hardware profile catalog schema")
    if profile.hardware_class not in HARDWARE_CLASSES[:-1]:
        raise ValueError("invalid hardware class")
    if profile.catalog_id not in {item.catalog_id for item in CATALOG}:
        raise ValueError("unknown hardware catalog entry")
    # A persisted record may vary only in per-instance identifiers (serials,
    # MAC and hostname). Every component that describes a physical platform
    # must correspond to one fully expanded catalog configuration; accepting
    # only the catalog ID would permit contradictory CPU/RAM/board records.
    platform_fields = (
        "catalog_id", "hardware_class", "platform", "cpu_vendor", "cpu_model",
        "cpu_family", "cpu_model_id", "cpu_stepping", "physical_cores",
        "logical_cpus", "cpu_mhz", "cache_kb", "socket", "chipset", "ram_mb",
        "gpu", "motherboard", "bios_vendor", "bios_version", "bios_date",
        "disk_model", "disk_size_mb", "network_adapter", "evidence_url",
    )
    if not any(all(getattr(profile, field) == getattr(item, field) for field in platform_fields)
               for item in CATALOG):
        raise ValueError("hardware profile does not match a compatible catalog configuration")
    if profile.physical_cores < 1 or profile.logical_cpus < profile.physical_cores:
        raise ValueError("inconsistent CPU core counts")
    if profile.ram_mb < 4096 or profile.ram_mb % 1024:
        raise ValueError("unrealistic RAM size")
    if not MIN_SYNTHETIC_DISK_MB <= profile.disk_size_mb <= MAX_SYNTHETIC_DISK_MB:
        raise ValueError("unrealistic disk size")
    if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", profile.mac):
        raise ValueError("invalid generated MAC")
    first = int(profile.mac[:2], 16)
    if first & 1 or not first & 2:
        raise ValueError("generated MAC is not locally administered and unicast")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", profile.hostname.lower()):
        raise ValueError("invalid generated hostname")
    for value in (profile.disk_serial, profile.system_serial, profile.board_serial, profile.chassis_serial):
        if not re.fullmatch(r"[A-Z0-9-]{7,16}", value):
            raise ValueError("invalid synthetic manufacturer serial")


def generate_hardware(hardware_class: str = "random") -> HardwareProfile:
    if hardware_class not in HARDWARE_CLASSES:
        raise ValueError(f"hardware class must be one of: {', '.join(HARDWARE_CLASSES)}")
    choices = CATALOG if hardware_class == "random" else tuple(
        item for item in CATALOG
        if item.hardware_class == hardware_class
        # Gaming desktop platforms are also valid conventional desktop PCs.
        # This is a selection alias, never a component mix or a new catalog
        # record; the persisted class remains the documented gaming-desktop.
        or (hardware_class == "desktop" and item.hardware_class == "gaming-desktop")
    )
    if not choices:
        raise ValueError(f"catalog contains no {hardware_class} configurations")
    item = secrets.choice(choices)
    result = HardwareProfile(
        catalog_id=item.catalog_id, catalog_schema_version=CATALOG_SCHEMA_VERSION,
        evidence_url=item.evidence_url, hardware_class=item.hardware_class,
        platform=item.platform, cpu_vendor=item.cpu_vendor, cpu_model=item.cpu_model,
        cpu_family=item.cpu_family, cpu_model_id=item.cpu_model_id, cpu_stepping=item.cpu_stepping,
        physical_cores=item.physical_cores, logical_cpus=item.logical_cpus,
        cpu_mhz=item.cpu_mhz, cache_kb=item.cache_kb, socket=item.socket, chipset=item.chipset,
        ram_mb=item.ram_mb, gpu=item.gpu, motherboard=item.motherboard,
        bios_vendor=item.bios_vendor, bios_version=item.bios_version, bios_date=item.bios_date,
        disk_model=item.disk_model, disk_size_mb=item.disk_size_mb,
        disk_serial=_manufacturer_serial(item.bios_vendor, "disk"),
        system_serial=_manufacturer_serial(item.bios_vendor, "system"),
        board_serial=_manufacturer_serial(item.bios_vendor, "board"),
        chassis_serial=_manufacturer_serial(item.bios_vendor, "chassis"),
        network_adapter=item.network_adapter, mac=_mac(), hostname=_hostname(item.hardware_class),
    )
    validate_hardware(result)
    return result
