"""Build data/attack_techniques.json from MITRE CTI enterprise ATT&CK STIX.

Usage: python scripts/build_attack_catalog.py [--out backend/src/log_whisperer/attack/attack_techniques.json]
"""

import argparse
import json
import urllib.request
from pathlib import Path

CTI_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def build(bundle: dict) -> dict:
    by_stix: dict[str, str] = {}
    techniques: dict[str, dict] = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        ref = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ref:
            continue
        tid = ref["external_id"]
        by_stix[obj["id"]] = tid
        techniques[tid] = {
            "name": obj.get("name", ""),
            "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                        if p.get("kill_chain_name") == "mitre-attack"],
            "url": ref.get("url", f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"),
            "deprecated": bool(obj.get("x_mitre_deprecated")) or bool(obj.get("revoked")),
            "revoked_by": None,
        }
    for obj in bundle["objects"]:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
            src, dst = by_stix.get(obj["source_ref"]), by_stix.get(obj["target_ref"])
            if src and dst:
                techniques[src]["revoked_by"] = dst
    return dict(sorted(techniques.items()))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path,
                    default=Path(__file__).parents[1] / "backend/src/log_whisperer/attack/attack_techniques.json")
    args = ap.parse_args()
    with urllib.request.urlopen(CTI_URL, timeout=300) as r:
        catalog = build(json.load(r))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(catalog, indent=0, ensure_ascii=False))
    print(f"{len(catalog)} techniques -> {args.out}")
