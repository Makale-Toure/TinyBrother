"""Detection engine: compiled Sigma rules indexed by channel and EventID."""

from __future__ import annotations

import logging
import time
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from tinybrother.attack.mapping import techniques_from_tags
from tinybrother.engine.compiler import EventPredicate, compile_rule
from tinybrother.engine.errors import UnsupportedRule
from tinybrother.engine.loader import load_rules
from tinybrother.engine.logsource import prepare_fields, targets_for
from tinybrother.engine.rule import SigmaRule
from tinybrother.models import Alert, Event, Severity

log = logging.getLogger(__name__)

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]


def severity_rank(level: str) -> int:
    try:
        return SEVERITY_ORDER.index(level.lower())
    except ValueError:
        return SEVERITY_ORDER.index("medium")


@dataclass
class CompiledRule:
    rule: SigmaRule
    predicate: EventPredicate
    severity: Severity
    hits: int = 0
    errors: int = 0


@dataclass
class LoadReport:
    loaded: int = 0
    unsupported: list[tuple[str, str]] = field(default_factory=list)  # (path, reason)
    parse_errors: list[tuple[str, str]] = field(default_factory=list)
    seconds: float = 0.0

    def reasons(self) -> Counter:
        return Counter(reason.split(":")[0].split(" '")[0] for _, reason in self.unsupported)


class DetectionEngine:
    def __init__(self, min_level: str = "informational") -> None:
        self.min_rank = severity_rank(min_level)
        self.rules: list[CompiledRule] = []
        # channel -> event_id -> rules ; channel -> rules matching any event id
        self._by_eid: dict[str, dict[int, list[CompiledRule]]] = defaultdict(lambda: defaultdict(list))
        self._by_channel: dict[str, list[CompiledRule]] = defaultdict(list)
        self.report = LoadReport()

    # ------------------------------------------------------------------ loading
    @classmethod
    def from_dirs(cls, dirs: Iterable[str | Path], min_level: str = "informational") -> DetectionEngine:
        engine = cls(min_level)
        start = time.perf_counter()
        errors: list[tuple[str, str]] = []
        for rule in load_rules(dirs, errors):
            engine.add_rule(rule)
        engine.report.parse_errors = errors
        engine.report.seconds = time.perf_counter() - start
        return engine

    def add_rule(self, rule: SigmaRule) -> bool:
        if severity_rank(rule.level) < self.min_rank:
            return False
        try:
            targets = targets_for(rule.logsource)
            predicate = compile_rule(rule)
            severity = Severity(rule.level) if rule.level in SEVERITY_ORDER else Severity.MEDIUM
        except UnsupportedRule as exc:
            self.report.unsupported.append((rule.path or rule.id, str(exc)))
            return False
        except Exception as exc:  # noqa: BLE001 - one broken rule must not kill the engine
            self.report.unsupported.append((rule.path or rule.id, f"compile error: {exc}"))
            return False

        compiled = CompiledRule(rule, predicate, severity)
        self.rules.append(compiled)
        for channel, eids in targets:
            if eids is None:
                self._by_channel[channel].append(compiled)
            else:
                for eid in eids:
                    self._by_eid[channel][eid].append(compiled)
        self.report.loaded += 1
        return True

    # ------------------------------------------------------------------ matching
    def candidates(self, event: Event) -> list[CompiledRule]:
        by_eid = self._by_eid.get(event.channel)
        specific = by_eid.get(event.event_id, []) if by_eid else []
        generic = self._by_channel.get(event.channel, [])
        return specific + generic if generic else specific

    def evaluate(self, event: Event) -> list[Alert]:
        rules = self.candidates(event)
        if not rules:
            return []
        fields = prepare_fields(event.channel, event.event_id, event.fields)
        alerts = []
        for cr in rules:
            try:
                matched = cr.predicate(fields)
            except Exception as exc:  # noqa: BLE001
                cr.errors += 1
                log.debug("rule %s failed on event: %s", cr.rule.id, exc)
                continue
            if matched:
                cr.hits += 1
                alerts.append(
                    Alert(
                        rule_id=cr.rule.id,
                        rule_title=cr.rule.title,
                        severity=cr.severity,
                        event=event,
                        techniques=techniques_from_tags(cr.rule.tags),
                        description=cr.rule.description,
                        rule_path=cr.rule.path,
                    )
                )
        alerts.sort(key=lambda a: severity_rank(a.severity.value), reverse=True)
        return alerts

    # ------------------------------------------------------------------ introspection
    def channels(self) -> set[str]:
        return set(self._by_eid) | set(self._by_channel)

    def rules_per_channel(self) -> Counter:
        c: Counter = Counter()
        for ch, eids in self._by_eid.items():
            c[ch] += len({id(r) for rules in eids.values() for r in rules})
        for ch, rules in self._by_channel.items():
            c[ch] += len(rules)
        return c
