"""Load Sigma YAML rules from disk."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path

import yaml

from tinybrother.engine.rule import SigmaRule


def load_rules(dirs: Iterable[str | Path]) -> Iterator[SigmaRule]:
    """Yield every valid Sigma rule found (recursively) in `dirs`."""
    for d in dirs:
        for path in sorted(Path(d).rglob("*.yml")):
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(doc, dict) or "detection" not in doc:
                continue
            yield SigmaRule(
                id=str(doc.get("id", path.stem)),
                title=doc.get("title", path.stem),
                level=doc.get("level", "medium"),
                logsource=doc.get("logsource", {}),
                detection=doc["detection"],
                tags=doc.get("tags", []),
                description=doc.get("description"),
                falsepositives=doc.get("falsepositives", []),
                path=str(path),
            )
