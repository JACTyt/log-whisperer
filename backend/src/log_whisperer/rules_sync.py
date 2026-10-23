"""Vendor a pinned, filtered SigmaHQ rule snapshot into rules/sigma/."""

import io
import json
import shutil
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

RELEASES_API = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest"
ARCHIVE_URL = "https://github.com/SigmaHQ/sigma/archive/refs/tags/{tag}.zip"

# Rule sub-trees whose logsources we support (DESIGN §7.1).
INCLUDE = [
    "rules/windows/builtin/security",
    "rules/windows/builtin/system",
    "rules/windows/builtin/application",
    "rules/windows/builtin/bits_client",
    "rules/windows/builtin/taskscheduler",
    "rules/windows/builtin/windefend",
    "rules/windows/process_creation",
    "rules/windows/network_connection",
    "rules/windows/file",
    "rules/windows/registry",
    "rules/windows/dns_query",
    "rules/windows/powershell",
    "rules/windows/process_access",
    "rules/windows/image_load",
    "rules/windows/create_remote_thread",
    "rules/windows/pipe_created",
    "rules/windows/driver_load",
    "rules/windows/wmi_event",
    "rules/windows/sysmon",
    "rules/linux/builtin",
    "rules/web/webserver_generic",
    "rules/web/product",
]


def latest_tag() -> str:
    with urllib.request.urlopen(RELEASES_API, timeout=30) as r:
        return json.load(r)["tag_name"]


def sync(dest: Path, tag: str | None = None) -> tuple[str, int]:
    """Download SigmaHQ `tag` (default: latest release) and copy supported rules into `dest`."""
    tag = tag or latest_tag()
    with urllib.request.urlopen(ARCHIVE_URL.format(tag=tag), timeout=120) as r:
        archive = zipfile.ZipFile(io.BytesIO(r.read()))
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    count = 0
    for info in archive.infolist():
        parts = PurePosixPath(info.filename).parts
        if len(parts) < 2 or info.is_dir():
            continue
        rel = PurePosixPath(*parts[1:])  # strip "sigma-<tag>/"
        if rel.name == "LICENSE" and len(rel.parts) == 1:
            (dest / "LICENSE").write_bytes(archive.read(info))
        if rel.suffix not in (".yml", ".yaml"):
            continue
        if not any(str(rel).startswith(prefix + "/") for prefix in INCLUDE):
            continue
        target = dest / PurePosixPath(*rel.parts[1:])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(archive.read(info))
        count += 1
    (dest / "VERSION").write_text(f"SigmaHQ {tag}\n{count} rule files\n")
    return tag, count
