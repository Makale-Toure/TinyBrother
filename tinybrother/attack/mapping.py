"""Extract ATT&CK techniques and tactics from Sigma tags.

Sigma tags look like `attack.execution`, `attack.t1059.001`.
"""

from __future__ import annotations

import re

from tinybrother.models import AttackTechnique

_TECH_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_TACTICS = {
    "reconnaissance", "resource_development", "initial_access", "execution",
    "persistence", "privilege_escalation", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact",
}


def techniques_from_tags(tags: list[str]) -> list[AttackTechnique]:
    """Return the ATT&CK techniques referenced in a rule's tags."""
    tactics = [t.split(".", 1)[1] for t in tags if t.lower().split(".", 1)[-1] in _TACTICS]
    techniques = []
    for tag in tags:
        m = _TECH_RE.match(tag.strip())
        if m:
            techniques.append(AttackTechnique(technique_id=m.group(1).upper(), tactics=tactics))
    return techniques
