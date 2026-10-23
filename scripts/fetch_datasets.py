"""Download public attack datasets into datasets/ (git-ignored). Safe to re-run: existing data is skipped.

- EVTX-ATTACK-SAMPLES (GPL-3.0) https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- Security-Datasets / Mordor (MIT) https://github.com/OTRF/Security-Datasets — a selection of Windows host recordings

Usage: python scripts/fetch_datasets.py [--dest datasets] [--only evtx|security]
"""

import argparse
import io
import urllib.request
import zipfile
from pathlib import Path

EVTX_ZIP = "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/archive/refs/heads/master.zip"
SECURITY_BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/"
SECURITY = {
    "mimikatz": "credential_access/host/empire_mimikatz_logonpasswords.zip",
    "sam-copy-esentutl": "credential_access/host/cmd_sam_copy_esentutl.zip",
    "psremoting": "lateral_movement/host/covenant_psremoting_command.zip",
    "bitsadmin": "defense_evasion/host/cmd_bitsadmin_download_psh_script.zip",
}
# Not included: some recordings contain live attack payloads that endpoint AV quarantines on download
# (e.g. empire_schtasks_creation_standard_user), and some lack the attack's own events.


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "log-whisperer/0.1"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.read()


def _extract(data: bytes, target: Path) -> None:
    """Extract a zip, refusing entries that would escape the target directory."""
    target.mkdir(parents=True, exist_ok=True)
    root = target.resolve()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            dest = (target / info.filename).resolve()
            if not dest.is_relative_to(root):
                raise ValueError(f"unsafe path in archive: {info.filename}")
        zf.extractall(target)


def fetch_evtx(dest: Path) -> None:
    target = dest / "evtx-attack-samples"
    if any(target.rglob("*.evtx")):
        print(f"skip  {target} (already present)")
        return
    print(f"fetch EVTX-ATTACK-SAMPLES -> {target}")
    _extract(_get(EVTX_ZIP), target)


def fetch_security(dest: Path) -> None:
    for name, rel in SECURITY.items():
        target = dest / "security-datasets" / name
        if any(target.glob("*.json")):
            print(f"skip  {target} (already present)")
            continue
        print(f"fetch {rel} -> {target}")
        _extract(_get(SECURITY_BASE + rel), target)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", type=Path, default=Path(__file__).parents[1] / "datasets")
    ap.add_argument("--only", choices=["evtx", "security"])
    args = ap.parse_args()
    if args.only in (None, "evtx"):
        fetch_evtx(args.dest)
    if args.only in (None, "security"):
        fetch_security(args.dest)
