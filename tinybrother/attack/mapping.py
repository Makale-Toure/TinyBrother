"""Extract ATT&CK techniques and tactics from Sigma tags.

Sigma tags look like `attack.execution`, `attack.defense-evasion` (current
SigmaHQ style) or `attack.defense_evasion` (older style), and `attack.t1059.001`.
"""

from __future__ import annotations

import re

from tinybrother.models import AttackTechnique

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
            techniques.append(AttackTechnique(technique_id=m.group(1).upper(), tactics=tactics))
    return techniques
