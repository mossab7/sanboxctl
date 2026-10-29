"""Compatible synthetic hardware profiles.

The catalog is deliberately made of complete platform variants.  We choose a
variant first and only then choose among values that are valid for that
variant; CPU, board, firmware, GPU, storage, and network hardware are never
mixed independently.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
import secrets
from typing import Any


HARDWARE_CLASSES = ("laptop", "desktop", "workstation", "random")

# The synthetic ``df`` helper and the staged /sys block-device view use MiB.
# Keep automatic identities within this ceiling so identity materialization can
# never fail after an otherwise valid profile has already been persisted.
MIN_SYNTHETIC_DISK_MB = 128_000
MAX_SYNTHETIC_DISK_MB = 1_048_576


@dataclass(frozen=True)
class HardwareProfile:
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
    ram_mb: int
    gpu: str
    motherboard: str
    bios_vendor: str
    bios_version: str
    bios_date: str
    disk_model: str
    disk_size_mb: int
    disk_serial: str
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
class _Variant:
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
    ram_options: tuple[int, ...]
    gpu: str
    motherboard: str
    bios_vendor: str
    bios_versions: tuple[str, ...]
    bios_date: str
    disk_options: tuple[tuple[str, int], ...]
    network_adapter: str


# These are coherent platform families, not claims about a particular host.
# The identifiers are public model names and the per-instance serial/MAC/
# hostname values are generated below.
CATALOG: tuple[_Variant, ...] = (
    _Variant("laptop", "Dell Latitude 5420", "GenuineIntel", "11th Gen Intel(R) Core(TM) i5-1145G7", 6, 140, 1, 4, 8, 2600, 8192, (8192, 16384), "Intel Iris Xe Graphics", "Dell 0H0YVY", "Dell Inc.", ("1.18.0", "1.24.0"), "2023-05-12", (("KIOXIA KBG40ZNS512G", 512000), ("WDC PC SN530 SDBPZK-512G", 512000)), "Intel Wi-Fi 6 AX201"),
    _Variant("laptop", "Lenovo ThinkPad T14 Gen 2 AMD", "AuthenticAMD", "AMD Ryzen 5 PRO 5650U with Radeon Graphics", 25, 80, 0, 6, 12, 2300, 16384, (16384, 32768), "AMD Radeon Graphics", "Lenovo 20XK", "LENOVO", ("R1BET62W", "R1MET62W"), "2023-02-08", (("SAMSUNG MZVLQ512HALU-00BL2", 512000), ("SK hynix PC711", 512000)), "Intel Wi-Fi 6 AX200"),
    _Variant("desktop", "HP EliteDesk 800 G6", "GenuineIntel", "12th Gen Intel(R) Core(TM) i7-12700", 6, 151, 2, 12, 20, 3600, 25600, (16384, 32768, 65536), "Intel UHD Graphics 770", "HP 8906", "HP", ("02.17.00", "02.20.00"), "2023-11-03", (("WD_BLACK SN770", 1000000), ("Samsung SSD 980 PRO", 1000000)), "Intel Ethernet Controller I225-V"),
    _Variant("desktop", "MSI MAG B550 Tomahawk", "AuthenticAMD", "AMD Ryzen 7 5800X 8-Core Processor", 25, 33, 0, 8, 16, 3800, 32768, (16384, 32768, 65536), "NVIDIA GeForce RTX 3060", "MSI MS-7C91", "American Megatrends International", ("A.90", "A.A0"), "2023-08-21", (("Crucial P5 Plus", 1000000), ("SAMSUNG MZ-V8P1T0", 1000000)), "Realtek RTL8125 2.5GbE"),
    _Variant("workstation", "Lenovo ThinkStation P620", "AuthenticAMD", "AMD Ryzen Threadripper PRO 3955WX 16-Cores", 25, 1, 0, 16, 32, 3900, 65536, (65536, 131072), "NVIDIA RTX A4000", "Lenovo 1036", "LENOVO", ("S07KT1B", "S07KT2B"), "2022-10-14", (("Samsung PM983", 960000), ("KIOXIA CD6", 960000)), "Intel Ethernet Connection I219-LM"),
    _Variant("workstation", "Dell Precision 5820 Tower", "GenuineIntel", "Intel(R) Xeon(R) W-2245 CPU", 6, 85, 7, 8, 16, 3900, 16384, (32768, 65536), "NVIDIA Quadro P2200", "Dell 0F5C5X", "Dell Inc.", ("2.13.0", "2.15.0"), "2022-06-16", (("Intel SSD D3-S4510", 960000), ("Micron 5300 PRO", 960000)), "Intel Ethernet I210"),
)


def _mac() -> str:
    raw = bytearray(secrets.token_bytes(6))
    raw[0] = (raw[0] & 0xFC) | 0x02
    return ":".join(f"{item:02x}" for item in raw)


def _serial() -> str:
    return "APP" + secrets.token_hex(7).upper()


def _hostname(hardware_class: str) -> str:
    return f"sbx-{hardware_class}-{secrets.token_hex(4)}"


def validate_hardware(profile: HardwareProfile) -> None:
    if profile.hardware_class == "legacy":
        return
    if profile.hardware_class not in HARDWARE_CLASSES[:-1]:
        raise ValueError("invalid hardware class")
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
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", profile.hostname):
        raise ValueError("invalid generated hostname")


def generate_hardware(hardware_class: str = "random") -> HardwareProfile:
    if hardware_class not in HARDWARE_CLASSES:
        raise ValueError(f"hardware class must be one of: {', '.join(HARDWARE_CLASSES)}")
    choices = CATALOG if hardware_class == "random" else tuple(item for item in CATALOG if item.hardware_class == hardware_class)
    variant = secrets.choice(choices)
    disk_model, disk_size_mb = secrets.choice(variant.disk_options)
    result = HardwareProfile(
        hardware_class=variant.hardware_class,
        platform=variant.platform,
        cpu_vendor=variant.cpu_vendor,
        cpu_model=variant.cpu_model,
        cpu_family=variant.cpu_family,
        cpu_model_id=variant.cpu_model_id,
        cpu_stepping=variant.cpu_stepping,
        physical_cores=variant.physical_cores,
        logical_cpus=variant.logical_cpus,
        cpu_mhz=variant.cpu_mhz,
        cache_kb=variant.cache_kb,
        ram_mb=secrets.choice(variant.ram_options),
        gpu=variant.gpu,
        motherboard=variant.motherboard,
        bios_vendor=variant.bios_vendor,
        bios_version=secrets.choice(variant.bios_versions),
        bios_date=variant.bios_date,
        disk_model=disk_model,
        disk_size_mb=disk_size_mb,
        disk_serial=_serial(),
        network_adapter=variant.network_adapter,
        mac=_mac(),
        hostname=_hostname(variant.hardware_class),
    )
    validate_hardware(result)
    return result


def legacy_hardware(profile: Any) -> HardwareProfile:
    """Represent an existing TOML profile without changing its behavior."""
    result = HardwareProfile(
        hardware_class="legacy",
        platform="Configured appsbx profile",
        cpu_vendor="appsbx",
        cpu_model="appsbx synthetic CPU",
        cpu_family=99,
        cpu_model_id=1,
        cpu_stepping=1,
        physical_cores=profile.synthetic_cpu_count,
        logical_cpus=profile.synthetic_cpu_count,
        cpu_mhz=1000,
        cache_kb=1024,
        ram_mb=profile.synthetic_ram_mb,
        gpu="appsbx synthetic GPU",
        motherboard="appsbx synthetic motherboard",
        bios_vendor="appsbx",
        bios_version="1",
        bios_date="1970-01-01",
        disk_model="appsbx synthetic disk",
        disk_size_mb=profile.synthetic_disk_mb,
        disk_serial="CONFIGURED",
        network_adapter="appsbx synthetic network adapter",
        mac=profile.synthetic_mac,
        hostname=profile.synthetic_hostname,
    )
    return result
