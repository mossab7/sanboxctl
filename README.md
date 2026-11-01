# Realms (appsbx)

Realms downloads the official Ankama Launcher, then launches it in separate Linux sandbox
profiles. Each realm has its own private application state, persistent
identity, and explicitly selected network path. The launcher and downloaded
game payload are managed separately so downloaded Dofus files do not have to
be duplicated for every realm.

## Install

Requirements: Linux x86-64, Python 3.10 or later, and one of `apt`, `dnf`,
`pacman`, or `zypper`. The installer detects the rest of the required host
tools and downloads the Linux launcher only from Ankama's published HTTPS
endpoint.

```bash
./install.sh check
./install.sh plan
./install.sh --yes
appsbx-gui
```

The default installation downloads, validates, extracts, and stages the
official Ankama Launcher into owner-only managed storage. No launcher path is
required. The GUI's **Choose Ankama Launcher…** option remains an advanced
recovery override; it copies the selected source rather than mounting it.

For a noninteractive install:

```bash
./install.sh --yes --skip-launcher-download
```

Use `--launcher /path/to/Ankama.AppImage` only as an advanced local override.
`--dry-run` prints planned actions without changing files. The installer
requires `--yes` before installing system packages or the narrowly restricted
real-network helper.

## First run

1. Run `appsbx-gui`, create a realm, and select its network path.
2. Launch it, sign in to the official launcher, and confirm Dofus installation.
3. Close Zaap after the download completes.

After a clean launcher exit, Realms verifies the official game manifest and
copies only its listed files to an immutable managed snapshot. Future realms
materialize that snapshot into their own writable game directory at the
expected location. On filesystems supporting reflinks this is block-level
copy-on-write; elsewhere it is a normal private copy. This is deliberate:
Zaap must create a per-realm release marker before it recognizes an existing
game as installed. No writable game files, logins, cookies, settings, key
material, logs, locks, or caches are shared between realms.

When an official update is required, stop all realms and choose **Update shared
game…**. It opens one temporary private update session. Download the official
update there and close Zaap; Realms then verifies and publishes a new snapshot.
It never modifies another realm's game directory. Existing realms retain their
known-good private game view; newly created realms use the newly published
snapshot. Refreshing an existing realm is intentionally a separate, explicit
maintenance action rather than an automatic cross-realm update.

## Updating and removal

```bash
./install.sh --update --yes
python3 -m appsbx.install uninstall
python3 -m appsbx.install uninstall --purge-state   # deletes every realm
```

An update preserves the managed launcher, game snapshots, and realm state.
Removal preserves state unless `--purge-state` is explicitly supplied.

## Boundaries and support

The GUI uses hardware graphics and the native desktop by default. GPU
acceleration necessarily exposes the real render device and driver to graphics
APIs; this is not a virtual machine. Real networking requires the privileged
helper installed by the installer. It is fail-closed for the selected egress;
stub mode remains offline.

For diagnostics and developer details, see [docs/](docs/). Do not copy browser
profiles, credentials, or game files directly between realms.
