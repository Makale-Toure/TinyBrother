from pathlib import Path

import yaml

from tinybrother.engine.compiler import compile_rule
from tinybrother.engine.engine import DetectionEngine
from tinybrother.engine.loader import load_rules
from tinybrother.engine.rule import SigmaRule
from tinybrother.normalizer.windows import from_xml

ROOT = Path(__file__).resolve().parent.parent
FIX = Path(__file__).parent / "fixtures"


def rule_from_yaml(text: str) -> SigmaRule:
    d = yaml.safe_load(text)
    return SigmaRule(
        id=d.get("id", "test"), title=d["title"], level=d.get("level", "medium"),
        logsource=d["logsource"], detection=d["detection"], tags=d.get("tags", []),
    )


SUSPICIOUS_PARENT = """
title: Office spawns shell
logsource: {product: windows, category: process_creation}
detection:
  selection_parent:
    ParentImage|endswith: ['\\\\winword.exe', '\\\\excel.exe']
  selection_child:
    - Image|endswith: '\\\\cmd.exe'
    - Image|endswith: '\\\\powershell.exe'
  filter:
    CommandLine|contains: 'legit'
  condition: all of selection_* and not filter
level: high
tags: [attack.execution, attack.t1204.002]
"""


def test_list_of_maps_and_filters():
    pred = compile_rule(rule_from_yaml(SUSPICIOUS_PARENT))
    base = {"ParentImage": "C:\\Office\\WINWORD.EXE", "Image": "C:\\x\\powershell.exe",
            "CommandLine": "powershell -c evil"}
    assert pred(base)
    assert not pred({**base, "CommandLine": "legit thing"})
    assert not pred({**base, "ParentImage": "C:\\explorer.exe"})


def test_keywords():
    pred = compile_rule(rule_from_yaml("""
title: kw
logsource: {product: windows, service: system}
detection:
  keywords: ['mimikatz', 'sekurlsa']
  condition: keywords
"""))
    assert pred({"Data_0": "running sekurlsa::logonpasswords"})
    assert not pred({"Data_0": "hello"})


def test_custom_rule_loads_and_fires_on_fixture():
    rules = list(load_rules([ROOT / "rules" / "custom"]))
    assert rules and rules[0].level == "high"

    engine = DetectionEngine.from_dirs([ROOT / "rules" / "custom"])
    assert engine.report.loaded >= 1
    event = from_xml((FIX / "sysmon_1.xml").read_text(encoding="utf-8"))
    alerts = engine.evaluate(event)
    assert [a.rule_title for a in alerts] == ["PowerShell Launched With Encoded Command"]
    assert {t.technique_id for t in alerts[0].techniques} == {"T1059.001", "T1027"}


def test_routing_skips_unrelated_events():
    engine = DetectionEngine.from_dirs([ROOT / "rules" / "custom"])
    event = from_xml((FIX / "security_4624.xml").read_text(encoding="utf-8"))
    assert engine.candidates(event) == []


def test_security_4688_aliases():
    engine = DetectionEngine()
    engine.add_rule(rule_from_yaml(SUSPICIOUS_PARENT))
    xml = (FIX / "security_4624.xml").read_text(encoding="utf-8")
    xml = xml.replace("<EventID>4624</EventID>", "<EventID>4688</EventID>").replace(
        '<Data Name="TargetUserName">makyt</Data>',
        '<Data Name="NewProcessName">C:\\Windows\\cmd.exe</Data>'
        '<Data Name="ParentProcessName">C:\\Office\\excel.exe</Data>'
        '<Data Name="CommandLine">cmd /c whoami</Data>',
    )
    alerts = engine.evaluate(from_xml(xml))
    assert len(alerts) == 1


def test_unsupported_rules_are_reported_not_raised():
    engine = DetectionEngine()
    ok = engine.add_rule(rule_from_yaml("""
title: agg
logsource: {product: windows, service: security}
detection:
  sel: {EventID: 4625}
  condition: sel | count() by IpAddress > 10
"""))
    assert not ok
    assert engine.report.unsupported
