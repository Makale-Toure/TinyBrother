"""Compile one Sigma field value (+ modifiers) into a predicate.

A predicate takes the event's field value (``str`` or ``None`` when the field
is absent) and returns ``True`` on match. Semantics follow the Sigma spec:

- matching is case-insensitive unless the ``cased`` modifier is used;
- ``*`` and ``?`` are wildcards, ``\\*``, ``\\?`` and ``\\\\`` are escapes;
- a list of values is OR-ed, or AND-ed with the ``all`` modifier;
- a ``null`` value matches an absent or empty field.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from collections.abc import Callable
from typing import Any

from tinybrother.engine.errors import UnsupportedRule

Predicate = Callable[[Any], bool]

MATCH_MODIFIERS = {"contains", "startswith", "endswith", "re", "cidr", "lt", "lte", "gt", "gte",
                   "exists", "fieldref"}
TRANSFORM_MODIFIERS = {"base64", "base64offset", "wide", "utf16le", "utf16be", "utf16", "windash"}
FLAG_MODIFIERS = {"all", "cased", "i", "m", "s"}

_WINDASH = ("-", "/", "–", "—", "―")  # -, /, en dash, em dash, horizontal bar


# --------------------------------------------------------------------------- wildcards
def _parse_wildcards(value: str) -> tuple[list[tuple[str, str]], bool]:
    """Split a Sigma string into ('lit', text) / ('any', '*') / ('one', '?') tokens."""
    tokens: list[tuple[str, str]] = []
    buf = []
    has_wildcard = False
    i = 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            buf.append(value[i + 1])
            i += 2
            continue
        if c in "*?":
            if buf:
                tokens.append(("lit", "".join(buf)))
                buf = []
            tokens.append(("any" if c == "*" else "one", c))
            has_wildcard = True
        else:
            buf.append(c)
        i += 1
    if buf:
        tokens.append(("lit", "".join(buf)))
    return tokens, has_wildcard


def _string_predicate(values: list[str], mode: str, cased: bool) -> Predicate:
    """OR of several Sigma strings with the same mode, compiled to native ops.

    mode: equals | contains | startswith | endswith. Plain literals become a
    set / tuple test; wildcard values are merged into one alternation regex.
    The field value is converted (and lower-cased) only once per call.
    """
    literals: list[str] = []
    patterns: list[str] = []
    for value in values:
        tokens, has_wildcard = _parse_wildcards(value)
        if not has_wildcard:
            lit = "".join(t for _, t in tokens)
            literals.append(lit if cased else lit.lower())
            continue
        body = "".join(
            re.escape(t) if kind == "lit" else (".*" if kind == "any" else ".")
            for kind, t in tokens
        )
        if mode in ("equals", "startswith"):
            body = "^" + body
        if mode in ("equals", "endswith"):
            body = body + "$"
        patterns.append(f"(?:{body})")

    rx = (
        re.compile("|".join(patterns), re.DOTALL | (0 if cased else re.IGNORECASE))
        if patterns else None
    )
    lit_rx = None
    lit_set = frozenset(literals)
    lit_tuple = tuple(literals)
    if mode == "contains" and len(literals) > 3:
        lit_rx = re.compile("|".join(re.escape(x) for x in sorted(literals, key=len, reverse=True)))

    def literal_match(s: str) -> bool:
        if not literals:
            return False
        if mode == "equals":
            return s in lit_set
        if mode == "startswith":
            return s.startswith(lit_tuple)
        if mode == "endswith":
            return s.endswith(lit_tuple)
        if lit_rx is not None:
            return lit_rx.search(s) is not None
        return any(x in s for x in lit_tuple)

    def predicate(v: Any) -> bool:
        if v is None:
            return False
        raw = v if isinstance(v, str) else str(v)
        if literal_match(raw if cased else getattr(raw, "low", None) or raw.lower()):
            return True
        return rx is not None and rx.search(raw) is not None

    return predicate


# --------------------------------------------------------------------------- transforms
def _to_bytes(v: str | bytes) -> bytes:
    return v if isinstance(v, bytes) else v.encode("utf-8")


def _base64offset(data: bytes) -> list[str]:
    start = (0, 2, 3)
    end = (None, -3, -2)
    return [
        base64.b64encode(i * b" " + data)[start[i]: end[(len(data) + i) % 3]].decode("ascii")
        for i in range(3)
    ]


def _apply_transform(mod: str, values: list[str | bytes]) -> list[str | bytes]:
    out: list[str | bytes] = []
    for v in values:
        if mod == "base64":
            out.append(base64.b64encode(_to_bytes(v)).decode("ascii"))
        elif mod == "base64offset":
            out.extend(_base64offset(_to_bytes(v)))
        elif mod in ("wide", "utf16le"):
            out.append(str(v).encode("utf-16-le"))
        elif mod == "utf16be":
            out.append(str(v).encode("utf-16-be"))
        elif mod == "utf16":
            out.append(str(v).encode("utf-16"))
        elif mod == "windash":
            s = str(v)
            variants = {s}
            for dash in _WINDASH:
                variants.add(re.sub(r"(^|\s)-", lambda m, d=dash: m.group(1) + d, s))
            out.extend(sorted(variants))
    return out


def _as_text(v: str | bytes) -> str:
    return v.decode("latin-1") if isinstance(v, bytes) else v


# --------------------------------------------------------------------------- main entry
def _single(value: Any, match: str | None, flags: set[str]) -> Predicate:
    cased = "cased" in flags

    if value is None:
        return lambda v: v is None or str(v) == ""

    if match == "re":
        rx_flags = 0
        if "i" in flags:
            rx_flags |= re.IGNORECASE
        if "m" in flags:
            rx_flags |= re.MULTILINE
        if "s" in flags:
            rx_flags |= re.DOTALL
        try:
            rx = re.compile(str(value), rx_flags)
        except re.error as exc:
            raise UnsupportedRule(f"invalid regex {value!r}: {exc}") from exc
        return lambda v: v is not None and rx.search(str(v)) is not None

    if match == "cidr":
        try:
            net = ipaddress.ip_network(str(value), strict=False)
        except ValueError as exc:
            raise UnsupportedRule(f"invalid cidr {value!r}") from exc

        def in_net(v: Any) -> bool:
            if v is None:
                return False
            try:
                return ipaddress.ip_address(str(v).strip()) in net
            except ValueError:
                return False

        return in_net

    if match in ("lt", "lte", "gt", "gte"):
        ref = float(value)
        op = {"lt": float.__lt__, "lte": float.__le__, "gt": float.__gt__, "gte": float.__ge__}[match]

        def compare(v: Any) -> bool:
            try:
                return v is not None and op(float(str(v)), ref)
            except ValueError:
                return False

        return compare

    return _string_predicate([_text(value)], _mode(match), cased)


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    return value if isinstance(value, str) else str(value)


def _mode(match: str | None) -> str:
    return match if match in ("contains", "startswith", "endswith") else "equals"


def compile_value(raw: Any, modifiers: list[str]) -> Predicate:
    """Compile a field value (scalar or list) with its modifier chain."""
    unknown = [m for m in modifiers if m not in MATCH_MODIFIERS | TRANSFORM_MODIFIERS | FLAG_MODIFIERS]
    if unknown:
        raise UnsupportedRule(f"unsupported modifier(s): {', '.join(unknown)}")
    if "fieldref" in modifiers:
        raise UnsupportedRule("fieldref is handled by the selection compiler")

    flags = {m for m in modifiers if m in FLAG_MODIFIERS}
    matches = [m for m in modifiers if m in MATCH_MODIFIERS]
    if len(matches) > 1:
        raise UnsupportedRule(f"conflicting modifiers: {matches}")
    match = matches[0] if matches else None

    values = raw if isinstance(raw, list) else [raw]

    if match == "exists":
        expected = bool(values[0]) if not isinstance(values[0], str) else values[0].lower() == "true"
        return lambda v: (v is not None and str(v) != "") == expected

    encoding = any(m in TRANSFORM_MODIFIERS - {"windash"} for m in modifiers)
    variant_lists: list[list[Any]] = []
    for original in values:
        variants: list[Any] = [original]
        for m in modifiers:
            if m in TRANSFORM_MODIFIERS:
                if original is None:
                    raise UnsupportedRule("transform modifier on null value")
                variants = _apply_transform(m, variants)
        variants = [_as_text(v) if isinstance(v, bytes) else v for v in variants]
        if encoding:
            # encoded values are literals: escape wildcard characters
            variants = [
                v.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
                for v in variants
            ]
        # an encoding + `contains`-less match makes no sense; Sigma rules always pair them
        variant_lists.append(variants)

    def build_groups() -> list[list[Predicate]]:
        return [[_single(v, match, flags) for v in vs] for vs in variant_lists]

    def group_match(g: list[Predicate], v: Any) -> bool:
        return any(p(v) for p in g)

    if "all" in flags:
        groups = build_groups()
        if len(groups) == 1 and len(groups[0]) == 1:
            return groups[0][0]
        return lambda v: all(group_match(g, v) for g in groups)

    # OR of everything: merge all string values into a single native predicate
    flat = [x for g in variant_lists for x in g]
    if match in (None, "contains", "startswith", "endswith"):
        strings = [_text(x) for x in flat if x is not None]
        preds: list[Predicate] = []
        if strings:
            preds.append(_string_predicate(strings, _mode(match), "cased" in flags))
        if any(x is None for x in flat):
            preds.append(lambda v: v is None or str(v) == "")
        if len(preds) == 1:
            return preds[0]
        return lambda v: any(p(v) for p in preds)
    all_preds = [p for g in build_groups() for p in g]
    if len(all_preds) == 1:
        return all_preds[0]
    return lambda v: any(p(v) for p in all_preds)
