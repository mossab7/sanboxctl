"""Managed immutable launcher and game payloads.

The store is deliberately outside every realm directory.  It contains only
official program bytes, never a realm HOME, cookies, keyrings, logs, or
launcher settings.  A game snapshot is accepted only when its own official
manifest enumerates every imported path.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .profile import ProfileError
from .rootfs import RootfsError, extract_appimage, inspect_appimage

STORE_MARKER = ".appsbx-game-store"
LAUNCHER_MARKER = ".appsbx-launcher-store"
GAME_RELATIVE = Path(".config/Ankama/Retro")
OFFICIAL_LAUNCHER_URL = "https://download.ankama.com/launcher/full/linux/x64"
MAX_LAUNCHER_BYTES = 2 * 1024 * 1024 * 1024
OFFICIAL_DOWNLOAD_HOSTS = {"download.ankama.com", "ankama.com", "www.ankama.com"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


class ApplicationStore:
    """Owner-only store for read-only, verified game snapshots."""

    def __init__(self, state_root: Path):
        self.root = (state_root / "application-store").resolve()
        self.games = self.root / "games"
        self.current = self.games / "retro-current.json"
        self.launchers = self.root / "launcher"
        self.launcher_config = self.launchers / "current.json"
        self.downloads = self.root / "downloads"
        self.launcher_download = self.downloads / "Ankama-Launcher-x86_64.AppImage"
        self.launcher_download_metadata = self.downloads / "Ankama-Launcher-x86_64.json"

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        marker = self.root / STORE_MARKER
        if not marker.exists():
            marker.write_text("appsbx immutable game store\n", encoding="ascii")
            os.chmod(marker, 0o600)
        elif marker.read_text(encoding="ascii") != "appsbx immutable game store\n":
            raise ProfileError("managed game-store marker is invalid")

    def launcher_root(self) -> Path | None:
        """Return the selected launcher only when it remains in this store."""
        try:
            data = json.loads(self.launcher_config.read_text(encoding="utf-8"))
            root = (self.launchers / str(data["directory"])).resolve(strict=True)
            if (not _inside(root, self.launchers.resolve()) or root.is_symlink()
                    or root.stat().st_mode & 0o022):
                return None
            executable = root / "zaap"
            if not executable.is_file() or executable.is_symlink() or not os.access(executable, os.X_OK):
                return None
            return root
        except (OSError, ValueError, TypeError):
            return None

    @staticmethod
    def _safe_copytree(source: Path, destination: Path) -> None:
        """Copy an AppDir without retaining symlinks that escape its root."""
        source = source.resolve(strict=True)
        for directory, names, files in os.walk(source, followlinks=False):
            directory_path = Path(directory)
            for name in [*names, *files]:
                candidate = directory_path / name
                if candidate.is_symlink():
                    try:
                        target = candidate.resolve(strict=True)
                    except OSError as exc:
                        raise ProfileError("launcher AppDir has a broken symlink") from exc
                    if not _inside(target, source):
                        raise ProfileError("launcher AppDir has a symlink outside the selected AppDir")
        shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copy2)

    @staticmethod
    def _tighten_tree(root: Path) -> None:
        for path in sorted(root.rglob("*"), reverse=True):
            if path.is_symlink():
                continue
            if path.is_dir():
                os.chmod(path, 0o755)
            elif path.is_file():
                mode = path.stat().st_mode
                os.chmod(path, 0o755 if mode & stat.S_IXUSR else 0o644)

    def stage_launcher(self, selected: Path) -> Path:
        """Copy/extract a user-selected AppDir or AppImage into managed state.

        The sandbox subsequently sees only the managed copy.  The original
        selected path is never bind-mounted, so a later replacement of it
        cannot change the executed launcher.
        """
        try:
            selected = selected.expanduser().resolve(strict=True)
        except OSError as exc:
            raise ProfileError("selected Ankama Launcher path is unavailable") from exc
        self._ensure_root()
        self.launchers.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.launchers, 0o700)
        temporary = Path(tempfile.mkdtemp(prefix=".launcher-", dir=self.launchers))
        staged = temporary / "zaap.AppDir"
        try:
            if selected.is_dir():
                self._safe_copytree(selected, staged)
            elif selected.is_file():
                try:
                    inspect_appimage(selected)
                    extract_appimage(selected, staged)
                except (RootfsError, OSError) as exc:
                    raise ProfileError("selected file is not a supported AppImage") from exc
            else:
                raise ProfileError("select an extracted AppDir or an AppImage file")
            executable = staged / "zaap"
            if not executable.is_file() or executable.is_symlink() or not os.access(executable, os.X_OK):
                raise ProfileError("selected launcher has no executable zaap file")
            self._tighten_tree(staged)
            digest = _sha256(executable)[:24]
            target_name = f"zaap-{digest}"
            target = self.launchers / target_name
            if target.exists():
                shutil.rmtree(temporary)
            else:
                os.replace(staged, target)
                temporary.rmdir()
            self.launcher_config.write_text(
                json.dumps({"directory": target_name, "zaap_sha256": _sha256(target / "zaap")}, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            os.chmod(self.launcher_config, 0o600)
            return target
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise

    @staticmethod
    def _validate_official_url(url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port:
            raise ProfileError("official launcher download URL must use plain HTTPS")
        hostname = (parsed.hostname or "").lower()
        if hostname not in OFFICIAL_DOWNLOAD_HOSTS and not hostname.endswith(".ankama.com"):
            raise ProfileError("official launcher download left Ankama-controlled hosts")

    def download_and_stage_official_launcher(self, url: str = OFFICIAL_LAUNCHER_URL) -> Path:
        """Fetch Ankama's published Linux AppImage into managed storage.

        The official support page publishes the stable endpoint but not a
        signed checksum. TLS, a strict redirect allow-list, AppImage parsing,
        and a recorded SHA-256 therefore provide transport/integrity checks;
        they are not presented as publisher-signature verification.
        """
        existing = self.launcher_root()
        if existing is not None:
            return existing
        self._validate_official_url(url)
        self._ensure_root()
        self.downloads.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.downloads, 0o700)
        if self.launcher_download.is_file():
            try:
                inspect_appimage(self.launcher_download)
                return self.stage_launcher(self.launcher_download)
            except (RootfsError, OSError, ProfileError):
                self.launcher_download.unlink(missing_ok=True)
                self.launcher_download_metadata.unlink(missing_ok=True)

        class _Redirects(HTTPRedirectHandler):
            def redirect_request(inner, request, fp, code, message, headers, newurl):
                self._validate_official_url(newurl)
                return super().redirect_request(request, fp, code, message, headers, newurl)

        temporary = self.launcher_download.with_suffix(".AppImage.part")
        temporary.unlink(missing_ok=True)
        request = Request(url, headers={"User-Agent": "appsbx-installer/1"})
        try:
            with build_opener(_Redirects()).open(request, timeout=60) as response, temporary.open("xb") as output:
                final_url = response.geturl()
                self._validate_official_url(final_url)
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isdigit() or int(length) > MAX_LAUNCHER_BYTES):
                    raise ProfileError("official launcher download has an invalid or excessive size")
                received = 0
                while chunk := response.read(1024 * 1024):
                    received += len(chunk)
                    if received > MAX_LAUNCHER_BYTES:
                        raise ProfileError("official launcher download exceeds the safety limit")
                    output.write(chunk)
            info = inspect_appimage(temporary)
            os.replace(temporary, self.launcher_download)
            self.launcher_download_metadata.write_text(json.dumps({
                "source": final_url, "sha256": info.sha256, "bytes": info.size,
            }, sort_keys=True) + "\n", encoding="utf-8")
            os.chmod(self.launcher_download_metadata, 0o600)
            return self.stage_launcher(self.launcher_download)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def game_root(self) -> Path | None:
        """Return the active immutable payload after validating its marker."""
        try:
            data = json.loads(self.current.read_text(encoding="utf-8"))
            root = (self.games / str(data["snapshot"])).resolve(strict=True)
            if not _inside(root, self.games.resolve()) or not (root / "manifest.json").is_file():
                return None
            if root.is_symlink() or root.stat().st_mode & 0o022:
                return None
            return root
        except (OSError, ValueError, TypeError):
            return None

    def import_retro(self, home: Path) -> Path:
        """Promote a completed official Retro payload without importing state.

        The official manifest is a strict allow-list.  The importer does not
        copy auxiliary files (including migration/account metadata) merely
        because they happen to live beside the installed game.
        """
        source = (home / GAME_RELATIVE).resolve(strict=True)
        if not source.is_dir() or source.is_symlink() or not _inside(source, home.resolve()):
            raise ProfileError("official game directory is unavailable")
        manifest = source / "manifest.json"
        try:
            entries = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ProfileError("official game manifest is invalid") from exc
        if not isinstance(entries, dict) or "dofus1electron" not in entries:
            raise ProfileError("official game manifest has no Dofus executable")
        allowed: list[Path] = []
        for raw, metadata in entries.items():
            relative = Path(raw)
            if (not isinstance(raw, str) or relative.is_absolute() or ".." in relative.parts
                    or not isinstance(metadata, dict) or not isinstance(metadata.get("size"), int)):
                raise ProfileError("official game manifest contains an unsafe entry")
            candidate = (source / relative).resolve(strict=True)
            if not _inside(candidate, source) or candidate.is_symlink() or not candidate.is_file():
                raise ProfileError("official game payload does not match its manifest")
            if candidate.stat().st_size != metadata["size"]:
                raise ProfileError("official game payload size does not match its manifest")
            allowed.append(relative)
        executable = source / "dofus1electron"
        if not os.access(executable, os.X_OK):
            raise ProfileError("official Dofus executable is not executable")
        self._ensure_root()
        self.games.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.games, 0o700)
        snapshot = "retro-" + _sha256(manifest)[:24]
        destination = self.games / snapshot
        if destination.is_dir():
            return destination
        temporary = Path(tempfile.mkdtemp(prefix=".retro-", dir=self.games))
        try:
            shutil.copy2(manifest, temporary / "manifest.json")
            for relative in allowed:
                target = temporary / relative
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                shutil.copy2(source / relative, target)
            for path in temporary.rglob("*"):
                if path.is_file(): os.chmod(path, 0o555 if os.access(path, os.X_OK) else 0o444)
                elif path.is_dir(): os.chmod(path, 0o555)
            os.replace(temporary, destination)
            self.current.write_text(json.dumps({"snapshot": snapshot, "manifest_sha256": _sha256(manifest)}, sort_keys=True) + "\n", encoding="utf-8")
            os.chmod(self.current, 0o600)
            return destination
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
