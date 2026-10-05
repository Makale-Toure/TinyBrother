"""Extract ATT&CK techniques and tactics from Sigma tags.

Sigma tags look like `attack.execution`, `attack.defense-evasion` (current
SigmaHQ style) or `attack.defense_evasion` (older style), and `attack.t1059.001`.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from tinybrother.models import AttackTechnique

_DATA = Path(__file__).parent / "data" / "enterprise.json"

_TECH_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

# kill-chain order, used for display. Recent ATT&CK versions split "defense-evasion"
# into "stealth" and "defense-impairment"; the legacy name is kept for older rules.
TACTICS = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "stealth", "defense-impairment", "defense-evasion",
    "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
]
_TACTIC_SET = set(TACTICS)


@lru_cache(maxsize=1)
def attack_data() -> dict:
    """Bundled ATT&CK knowledge base (see scripts/update_attack_data.py)."""
    try:
        return json.loads(_DATA.read_text(encoding="utf-8"))
    except FileNotFoundError:  # pragma: no cover
        return {"attack_version": None, "tactics": {}, "techniques": {}}


def technique_info(technique_id: str) -> dict | None:
    return attack_data()["techniques"].get(technique_id.upper())


def technique_label(technique_id: str) -> str:
    """'T1059.001' -> 'PowerShell' ; unknown IDs are returned unchanged."""
    info = technique_info(technique_id)
    return info["name"] if info else technique_id


def tactics_for(technique_id: str, rule_tactics: list[str]) -> list[str]:
    """Tactics under which a technique should be shown.

    A rule tagged (execution, credential-access, T1003) should place T1003 under
    credential-access only: keep the rule tactics that ATT&CK lists for the
    technique, fall back to ATT&CK's own tactics, then to the rule's.
    """
    info = technique_info(technique_id)
    official = [normalize_tactic(t) for t in info["tactics"]] if info else []
    both = [t for t in rule_tactics if t in official]
    return both or official or list(rule_tactics) or ["unknown"]


def normalize_tactic(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def tactics_from_tags(tags: list[str]) -> list[str]:
    out = []
    for tag in tags:
        if not tag.lower().startswith("attack."):
            continue
        t = normalize_tactic(tag.split(".", 1)[1])
        if t in _TACTIC_SET and t not in out:
            out.append(t)
    return out


def techniques_from_tags(tags: list[str]) -> list[AttackTechnique]:
    """Return the ATT&CK techniques referenced in a rule's tags."""
    tactics = tactics_from_tags(tags)
    techniques = []
    for tag in tags:
        m = _TECH_RE.match(tag.strip())
        if m:
            tid = m.group(1).upper()
            techniques.append(AttackTechnique(technique_id=tid, name=technique_label(tid), tactics=tactics))
    return techniques
