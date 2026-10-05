"""Build tinybrother/attack/data/enterprise.json from MITRE's ATT&CK STIX bundle.

Keeps only what the dashboard and CLI need: technique id, name, parent name,
tactics, a one-sentence description and the URL. Revoked/deprecated techniques
are kept (older Sigma rules still reference them) and flagged.

Usage:
    python scripts/update_attack_data.py                 # download the latest bundle
    python scripts/update_attack_data.py --file enterprise-attack.json

ATT&CK® is a registered trademark of The MITRE Corporation; data © MITRE,
used under the ATT&CK terms of use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.request
from pathlib import Path

URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
       "enterprise-attack/enterprise-attack.json")
OUT = Path(__file__).resolve().parent.parent / "tinybrother" / "attack" / "data" / "enterprise.json"

_CITATION = re.compile(r"\(Citation:[^)]*\)")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_CODE = re.compile(r"<code>(.*?)</code>")


def first_sentence(text: str, limit: int = 240) -> str:
    text = _CODE.sub(r"\1", _LINK.sub(r"\1", _CITATION.sub("", text or "")))
    text = " ".join(text.split())
    m = re.search(r"^(.+?[.!?])(\s|$)", text)
    s = m.group(1) if m else text
    return s if len(s) <= limit else s[: limit - 1].rstrip() + "…"


def external_id(obj: dict) -> tuple[str, str] | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("T"):
            return ref["external_id"], ref.get("url", "")
    return None


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--file", type=Path, help="local enterprise-attack.json")
    args = p.parse_args()
    if args.file:
        bundle = json.loads(args.file.read_text(encoding="utf-8"))
    else:
        print(f"Downloading {URL} ...")
        with urllib.request.urlopen(URL) as resp:
            bundle = json.loads(resp.read())

    objects = bundle["objects"]
    version = next((o.get("x_mitre_version") for o in objects if o["type"] == "x-mitre-collection"), "?")
    tactics = {
        o["x_mitre_shortname"]: o["name"]
        for o in objects if o["type"] == "x-mitre-tactic" and not o.get("revoked")
    }

    techniques: dict[str, dict] = {}
    for o in objects:
        if o["type"] != "attack-pattern":
            continue
        ext = external_id(o)
        if not ext:
            continue
        tid, url = ext
        entry = {
            "name": o.get("name", tid),
            "tactics": [k["phase_name"] for k in o.get("kill_chain_phases", [])
                        if k.get("kill_chain_name") == "mitre-attack"],
            "description": first_sentence(o.get("description", "")),
            "url": url,
        }
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            entry["deprecated"] = True
        # prefer the active object if an ID appears twice
        if tid in techniques and not techniques[tid].get("deprecated"):
            continue
        techniques[tid] = entry

    for tid, entry in techniques.items():
        if "." in tid:
            parent = techniques.get(tid.split(".")[0])
            if parent:
                entry["parent"] = parent["name"]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    data = {"attack_version": version, "tactics": tactics,
            "techniques": dict(sorted(techniques.items()))}
    OUT.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"ATT&CK v{version}: {len(techniques)} techniques, {len(tactics)} tactics -> {OUT}")


if __name__ == "__main__":
    main()
