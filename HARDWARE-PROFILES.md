# Automatic hardware profiles

`--identity auto` creates one fresh identity state directory for each launch.
The directory is allocated with an atomic `mkdir` below
`sandbox-state/.auto/`; it is owner-only and is never shared with the named
profile's persistent home. `secrets` supplies the machine ID, boot ID,
hostname suffix, locally administered unicast MAC, and disk serial.

The catalog chooses a complete platform variant before choosing compatible
options. Current families include Intel and AMD laptops, Intel and AMD
desktops, and Intel Xeon/AMD Threadripper workstations. Each variant binds a
CPU generation to plausible core counts, RAM options, firmware, board, GPU,
storage, and network adapter. `random` chooses among those families. It does
not inspect the host to choose a model.

Example:

```text
./sandboxctl run --profile example --identity auto --hardware-class laptop \
  --mode stub --display xvfb --execute -- /opt/app/zaap
./sandboxctl identity inspect example
```

The named profile default remains persistent for compatibility. Automatic
identities are retained under `.auto` so an operator can inspect the exact
profile after a run; they can be removed only by an explicit, separately
reviewed state-retention cleanup operation.

## What is virtualized

The generated values are rendered into Bubblewrap-mounted files for:

- `/etc/machine-id`, hostname, passwd/group, and os-release;
- `/proc/cpuinfo`, `/proc/meminfo`, and selected process/kernel files;
- CPU topology/frequency compatibility files under `/sys/devices/system/cpu`;
- DMI vendor, product, board, and BIOS files under `/sys/class/dmi/id`;
- a synthetic `/sys/block/vda` disk model, serial, and size;
- the private `df` compatibility command, using the generated disk capacity.

All child processes inherit the same mount namespace and therefore the same
files. The application root and runtime closure remain read-only; only the
profile-private home is writable.

## What is not spoofed

This feature does not emulate hardware or change the kernel. It does not
spoof CPUID, `sysinfo(2)`, GPU ioctls/drivers, PCI/USB enumeration, timing,
thermal sensors, instruction-set behavior, or every possible `/sys` path.
Node/Electron APIs implemented through those paths can still disagree with
the synthetic files. Native addons and subprocesses require separate review.
The network namespace and selected-egress firewall remain the security
boundary for network identity; generated adapter names are descriptive data,
not a replacement for kernel network interfaces.
