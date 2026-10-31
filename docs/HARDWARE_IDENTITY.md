# Hardware identity catalog

`sandboxctl` gives every GUI realm a persistent synthetic hardware profile.
The profile is created when the realm is created, written to its private
`identity/identity.json`, registered transactionally in
`identity-registry.sqlite3`, and reused for every later launch.  Deleting a
realm retires its registry row; the identifier values are never issued again.

## Catalog

`catalog/hardware_templates.json` is schema version 1.  It contains documented
desktop platform families and a source URL for each family.  The loader expands
only the declared BIOS versions, RAM capacities, and SSD choices for the same
family.  The current five families expand to 320 configurations:

- Dell Latitude 5420 and Lenovo ThinkPad T14 Gen 2 laptops;
- HP EliteDesk 800 G6 desktop and ASUS Z690 gaming desktop;
- Lenovo ThinkStation P620 workstation.

The expansion is a compatibility matrix, not a claim that every expanded
combination was shipped as an individual manufacturer SKU.  CPU, socket,
chipset, board, firmware, GPU, NIC, memory, and disk options are never mixed
between families.

## Per-realm values

The generator uses operating-system cryptographic randomness for locally
administered unicast MAC addresses, hostnames, storage serials, system/board/
chassis serials, machine ID, boot ID, and a registry-backed hardware UUID.
These are independent for clones.  A clone copies only the selected network
setting; it does not copy identity, browser/session state, game data, locks,
or credentials.

## Linux surfaces staged by the sandbox

The persistent profile is materialized into the read-only identity files that
the Bubblewrap plan binds over these paths:

- `/etc/machine-id`, `/etc/hostname`, hosts and NSS identity files;
- synthetic `/proc/cpuinfo`, memory, CPU topology, disk, boot-ID and kernel
  identity files;
- staged CPU topology and frequency files under `/sys/devices/system/cpu`;
- staged DMI vendor, product, board, BIOS, UUID and serial files under
  `/sys/class/dmi/id`;
- the synthetic `vda` model, serial, and capacity files under `/sys/block`.

The renderer and the root filesystem use the same `HardwareProfile`, so DMI,
storage, host name, CPU count, and RAM capacity do not intentionally disagree.
The test suite checks this materialization directly.

## Physical-GPU limitation

Hardware GPU mode intentionally exposes one real DRM render node and the
minimal sysfs/driver topology required by Mesa.  Consequently a process can
observe the physical GPU vendor/device IDs, PCI address, kernel/Mesa driver,
and EGL/OpenGL renderer through DRM ioctls and graphics APIs.  Those properties
cannot be made consistent with an arbitrary catalog GPU without losing native
acceleration or writing a GPU virtualization layer.  The catalog GPU field is
therefore a synthetic platform description, not a guarantee about the physical
GPU visible to an accelerated process.

The sandbox does not expose DRM control nodes, the whole host sysfs hierarchy,
host DMI data, or other PCI devices merely because hardware acceleration is
enabled.
