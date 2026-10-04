"""Load Sigma YAML rules from disk."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path

import yaml

from tinybrother.engine.rule import SigmaRule

# libyaml-based loader is ~10x faster when available (bundled in PyYAML wheels)
_Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def load_rules(
    dirs: Iterable[str | Path], errors: list[tuple[str, str]] | None = None
) -> Iterator[SigmaRule]:
    """Yield every Sigma rule found (recursively) in `dirs`.

    Files that cannot be parsed are reported in `errors` as (path, reason).
    """
    for d in dirs:
        base = Path(d)
        if not base.exists():
            continue
        files = sorted(base.rglob("*.yml")) + sorted(base.rglob("*.yaml"))
        for path in files:
            try:
                text = path.read_text(encoding="utf-8")
                docs = [doc for doc in yaml.load_all(text, Loader=_Loader) if doc]
            except yaml.YAMLError as exc:
                if errors is not None:
                    errors.append((str(path), f"YAML error: {exc}"))
                continue
            if len(docs) != 1:
                if errors is not None:
                    errors.append((str(path), "multi-document rule collections not supported"))
                continue
            doc = docs[0]
            if not isinstance(doc, dict) or "detection" not in doc:
                continue  # not a detection rule (e.g. correlation or config file)
            yield SigmaRule(
                id=str(doc.get("id", path.stem)),
                title=str(doc.get("title", path.stem)),
                level=str(doc.get("level", "medium")).lower(),
                logsource=doc.get("logsource") or {},
                detection=doc["detection"],
                tags=[str(t) for t in _as_list(doc.get("tags"))],
                description=doc.get("description"),
                falsepositives=[str(f) for f in _as_list(doc.get("falsepositives"))],
                status=doc.get("status"),
                author=doc.get("author"),
                references=[str(r) for r in _as_list(doc.get("references"))],
                path=str(path),
            )
