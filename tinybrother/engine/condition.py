"""Sigma condition parser.

Grammar (lowest to highest precedence)::

    expr    := and_expr ("or" and_expr)*
    and_expr:= not_expr ("and" not_expr)*
    not_expr:= "not" not_expr | primary
    primary := "(" expr ")"
             | ("1" | "any" | "all") "of" (pattern | "them")
             | identifier

Selections are bound at compile time, so the result is directly a predicate
``evaluate(fields) -> bool``; ``and`` / ``or`` short-circuit, so selections are
only evaluated when needed.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable
from typing import Any

from tinybrother.engine.errors import UnsupportedRule

Fields = Any
Selection = Callable[[Fields], bool]
Node = Callable[[Fields], bool]

_TOKEN_RE = re.compile(r"\s*(\(|\)|[^\s()]+)")
_KEYWORDS = {"and", "or", "not", "of", "them", "1", "all", "any"}


def tokenize(condition: str) -> list[str]:
    if "|" in condition:
        raise UnsupportedRule("aggregation conditions (| count() ...) are not supported")
    tokens = _TOKEN_RE.findall(condition)
    if not tokens:
        raise UnsupportedRule("empty condition")
    return tokens


class _Parser:
    def __init__(self, tokens: list[str], selections: dict[str, Selection]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.sel = selections
        self.names = list(selections)

    # helpers
    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise UnsupportedRule("unexpected end of condition")
        self.pos += 1
        return tok

    def expect(self, value: str) -> None:
        tok = self.take()
        if tok.lower() != value:
            raise UnsupportedRule(f"expected {value!r}, got {tok!r}")

    # grammar
    def parse(self) -> Node:
        node = self.expr()
        if self.peek() is not None:
            raise UnsupportedRule(f"unexpected token {self.peek()!r}")
        return node

    def expr(self) -> Node:
        nodes = [self.and_expr()]
        while (self.peek() or "").lower() == "or":
            self.take()
            nodes.append(self.and_expr())
        if len(nodes) == 1:
            return nodes[0]
        return lambda f, ns=tuple(nodes): any(n(f) for n in ns)

    def and_expr(self) -> Node:
        nodes = [self.not_expr()]
        while (self.peek() or "").lower() == "and":
            self.take()
            nodes.append(self.not_expr())
        if len(nodes) == 1:
            return nodes[0]
        return lambda f, ns=tuple(nodes): all(n(f) for n in ns)

    def not_expr(self) -> Node:
        if (self.peek() or "").lower() == "not":
            self.take()
            inner = self.not_expr()
            return lambda f: not inner(f)
        return self.primary()

    def primary(self) -> Node:
        tok = self.take()
        low = tok.lower()
        if tok == "(":
            node = self.expr()
            self.expect(")")
            return node
        if low in ("1", "any", "all") and (self.peek() or "").lower() == "of":
            self.take()
            target = self.take()
            if target.lower() == "them":
                names = [n for n in self.names if not n.startswith("_")]
            else:
                names = [n for n in self.names if fnmatch.fnmatchcase(n, target)]
            if not names:
                raise UnsupportedRule(f"'{tok} of {target}' matches no selection")
            preds = tuple(self.sel[n] for n in names)
            if low == "all":
                return lambda f: all(p(f) for p in preds)
            return lambda f: any(p(f) for p in preds)
        if low in _KEYWORDS or tok == ")":
            raise UnsupportedRule(f"unexpected token {tok!r}")
        if tok not in self.names:
            raise UnsupportedRule(f"condition references unknown selection {tok!r}")
        return self.sel[tok]


def parse_condition(condition: str | list[str], selections: dict[str, Selection]) -> Node:
    """Compile a Sigma condition (a list of conditions is OR-ed) into a predicate."""
    conditions = condition if isinstance(condition, list) else [condition]
    nodes = [_Parser(tokenize(str(c)), selections).parse() for c in conditions]
    if len(nodes) == 1:
        return nodes[0]
    return lambda f: any(n(f) for n in nodes)
