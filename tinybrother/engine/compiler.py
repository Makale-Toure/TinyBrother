"""Compile a SigmaRule's detection section into a fast predicate."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from tinybrother.engine.condition import parse_condition
from tinybrother.engine.errors import UnsupportedRule
from tinybrother.engine.modifiers import compile_value
from tinybrother.engine.rule import SigmaRule

Fields = Mapping[str, Any]
EventPredicate = Callable[[Fields], bool]

_IGNORED_KEYS = {"condition", "timeframe"}


def _keyword_predicate(values: list[Any], modifiers: list[str]) -> EventPredicate:
    """Keyword search: any value matches any field value (substring semantics)."""
    mods = modifiers or ["contains"]
    pred = compile_value(values, mods)
    return lambda fields: any(pred(v) for v in fields.values() if v is not None)


def _fieldref_predicate(field: str, other: Any, modifiers: list[str]) -> EventPredicate:
    others = other if isinstance(other, list) else [other]
    rest = [m for m in modifiers if m != "fieldref"]
    if rest not in ([], ["contains"], ["startswith"], ["endswith"]):
        raise UnsupportedRule(f"fieldref with {rest} not supported")
    mode = rest[0] if rest else "equals"

    def check(fields: Fields) -> bool:
        v = fields.get(field)
        if v is None:
            return False
        v = str(v).lower()
        for o in others:
            ref = fields.get(str(o))
            if ref is None:
                continue
            ref = str(ref).lower()
            if (
                (mode == "equals" and v == ref)
                or (mode == "contains" and ref in v)
                or (mode == "startswith" and v.startswith(ref))
                or (mode == "endswith" and v.endswith(ref))
            ):
                return True
        return False

    return check


def _map_predicate(mapping: dict) -> EventPredicate:
    """All field conditions of a map must match (AND)."""
    preds: list[EventPredicate] = []
    for key, value in mapping.items():
        key = str(key)
        field, *modifiers = key.split("|")
        if "expand" in modifiers:
            raise UnsupportedRule("expand modifier (placeholders) not supported")
        if field == "":
            preds.append(_keyword_predicate(value if isinstance(value, list) else [value], modifiers))
            continue
        if "fieldref" in modifiers:
            preds.append(_fieldref_predicate(field, value, modifiers))
            continue
        if isinstance(value, dict):
            raise UnsupportedRule(f"nested map under field {field!r}")
        vp = compile_value(value, modifiers)
        preds.append(lambda f, name=field, p=vp: p(f.get(name)))
    if len(preds) == 1:
        return preds[0]
    return lambda f: all(p(f) for p in preds)


def compile_selection(item: Any) -> EventPredicate:
    if isinstance(item, dict):
        return _map_predicate(item)
    if isinstance(item, list):
        if all(isinstance(x, dict) for x in item):
            preds = [_map_predicate(x) for x in item]
            return lambda f: any(p(f) for p in preds)
        if all(not isinstance(x, (dict, list)) for x in item):
            return _keyword_predicate(item, [])
        raise UnsupportedRule("mixed list of maps and keywords")
    if isinstance(item, (str, int)):
        return _keyword_predicate([item], [])
    raise UnsupportedRule(f"unsupported selection type {type(item).__name__}")


def compile_rule(rule: SigmaRule) -> EventPredicate:
    """Return ``predicate(fields) -> bool`` for the whole rule."""
    detection = rule.detection
    if "condition" not in detection:
        raise UnsupportedRule("missing condition")
    selections = {
        str(name): compile_selection(body)
        for name, body in detection.items()
        if name not in _IGNORED_KEYS
    }
    return parse_condition(detection["condition"], selections)
