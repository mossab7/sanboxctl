"""Strict TOML profile loading and validation."""

from __future__ import annotations

from dataclasses import dataclass
import re
from pathlib import Path
from typing import Any
import tomllib
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
LOCALE_RE = re.compile(r"^(?:C|POSIX|[A-Za-z]{2,3}(?:_[A-Za-z]{2,4})?(?:\.[A-Za-z0-9_-]+)?)$")
ALLOWED_KEYS = {
    "id", "default_egress", "timezone", "locale", "synthetic_hostname",
    "synthetic_mac", "synthetic_cpu_count", "synthetic_ram_mb",
    "synthetic_disk_mb",
    "runtime_uid", "runtime_gid",
}


class ProfileError(ValueError):
    """Raised when a profile is malformed or unsafe to use."""


@dataclass(frozen=True)
class Profile:
    name: str
    profile_id: int
    default_egress: str | None
    timezone: str
    locale: str
    synthetic_hostname: str
    synthetic_mac: str
    synthetic_cpu_count: int
    synthetic_ram_mb: int
    synthetic_disk_mb: int
    runtime_uid: int
    runtime_gid: int


def _required(data: dict[str, Any], key: str) -> Any:
    if key not in data:
        raise ProfileError(f"missing required field: {key}")
    return data[key]


def _integer(data: dict[str, Any], key: str, minimum: int, maximum: int) -> int:
    value = _required(data, key)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ProfileError(f"{key} must be an integer in [{minimum}, {maximum}]")
    return value


def load_profile(path: Path, name: str | None = None) -> Profile:
    profile_name = name or path.stem
    if not NAME_RE.fullmatch(profile_name):
        raise ProfileError(f"invalid profile name: {profile_name!r}")
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except OSError as exc:
        raise ProfileError(f"cannot read profile {profile_name}: {exc}") from exc
    unknown = set(data) - ALLOWED_KEYS
    if unknown:
        raise ProfileError(f"unknown profile fields: {', '.join(sorted(unknown))}")

    profile_id = _integer(data, "id", 0, 253)
    timezone = _required(data, "timezone")
    if not isinstance(timezone, str) or not timezone or timezone.startswith("/"):
        raise ProfileError("timezone must be a named zone")
    try:
        ZoneInfo(timezone)
    except ZoneInfoNotFoundError as exc:
        raise ProfileError(f"unknown timezone: {timezone}") from exc

    locale = _required(data, "locale")
    if not isinstance(locale, str) or not LOCALE_RE.fullmatch(locale):
        raise ProfileError("locale has an unsupported format")
    hostname = _required(data, "synthetic_hostname")
    if not isinstance(hostname, str) or len(hostname) > 253 or not HOSTNAME_RE.fullmatch(hostname.lower()):
        raise ProfileError("synthetic_hostname is not a valid DNS hostname")
    mac = _required(data, "synthetic_mac")
    if not isinstance(mac, str) or not MAC_RE.fullmatch(mac.lower()):
        raise ProfileError("synthetic_mac must be six colon-separated hex octets")
    first_octet = int(mac[:2], 16)
    if first_octet & 1 or not first_octet & 2:
        raise ProfileError("synthetic_mac must be locally administered and unicast")

    default_egress = data.get("default_egress")
    if default_egress is not None and (not isinstance(default_egress, str) or not re.fullmatch(r"^[a-z][a-z0-9_-]{0,31}$", default_egress)):
        raise ProfileError("default_egress has an invalid name")

    return Profile(
        name=profile_name,
        profile_id=profile_id,
        default_egress=default_egress,
        timezone=timezone,
        locale=locale,
        synthetic_hostname=hostname.lower(),
        synthetic_mac=mac.lower(),
        synthetic_cpu_count=_integer(data, "synthetic_cpu_count", 1, 256),
        synthetic_ram_mb=_integer(data, "synthetic_ram_mb", 128, 1_048_576),
        # The compatibility df command reports this fixed capacity as wholly
        # available. It is deliberately profile data, never a host query.
        synthetic_disk_mb=_integer(data, "synthetic_disk_mb", 1_024, 1_048_576),
        runtime_uid=_integer(data, "runtime_uid", 1, 65_534),
        runtime_gid=_integer(data, "runtime_gid", 1, 65_534),
    )


def load_profiles(directory: Path) -> dict[str, Profile]:
    profiles: dict[str, Profile] = {}
    ids: dict[int, str] = {}
    macs: dict[str, str] = {}
    if not directory.exists():
        return profiles
    for path in sorted(directory.glob("*.toml")):
        profile = load_profile(path)
        if profile.name in profiles:
            raise ProfileError(f"duplicate profile: {profile.name}")
        if profile.profile_id in ids:
            raise ProfileError(f"profile id {profile.profile_id} used by {ids[profile.profile_id]} and {profile.name}")
        if profile.synthetic_mac in macs:
            raise ProfileError(f"synthetic MAC used by {macs[profile.synthetic_mac]} and {profile.name}")
        profiles[profile.name] = profile
        ids[profile.profile_id] = profile.name
        macs[profile.synthetic_mac] = profile.name
    return profiles
