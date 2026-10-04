from pathlib import Path

from tinybrother.engine.loader import load_rules

ROOT = Path(__file__).resolve().parent.parent


def test_loads_custom_rules():
    rules = list(load_rules([ROOT / "rules" / "custom"]))
    assert rules, "expected at least one custom rule"
    rule = rules[0]
    assert rule.level == "high"
    assert "condition" in rule.detection
