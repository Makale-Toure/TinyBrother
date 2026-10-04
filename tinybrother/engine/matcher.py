"""Evaluate Sigma detections against events.

Milestone 2 scope: selections (maps and lists of maps), field modifiers
(contains, startswith, endswith, re, all, cased), wildcards, and conditions
with and/or/not, parentheses, `1 of X*`, `all of them`.
"""

from __future__ import annotations

from tinybrother.engine.rule import SigmaRule
from tinybrother.models import Event


def matches(rule: SigmaRule, event: Event) -> bool:
    raise NotImplementedError("milestone 2")
