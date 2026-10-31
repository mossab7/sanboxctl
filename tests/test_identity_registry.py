from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest
import uuid

from appsbx.identity_registry import IdentityRegistry, IdentityRegistryError, RegisteredIdentity


def record(index: int) -> RegisteredIdentity:
    return RegisteredIdentity(str(uuid.uuid4()), str(uuid.uuid4()), f"{index:032x}", f"DESKTOP-{index:07X}", f"02:00:00:{index >> 16 & 255:02x}:{index >> 8 & 255:02x}:{index & 255:02x}", f"SERIAL{index:06d}")


class IdentityRegistryTests(unittest.TestCase):
    def test_concurrent_issuance_and_retirement_never_reuses_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = IdentityRegistry(Path(directory) / "identities.sqlite3")
            values = [record(index) for index in range(128)]
            with ThreadPoolExecutor(max_workers=12) as pool:
                list(pool.map(registry.register, values))
            self.assertTrue(all(registry.is_registered(value.instance_uuid) for value in values))
            registry.retire(values[0].instance_uuid)
            with self.assertRaises(IdentityRegistryError):
                registry.register(values[0])

