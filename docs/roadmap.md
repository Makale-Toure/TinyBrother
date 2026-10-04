# Roadmap

## Milestone 0: Scaffold ✅
Repository layout, packaging, CI, README, example rule.

## Milestone 1: Collection ✅
- [x] `normalizer.windows.from_xml` with unit tests on sample XML
- [x] `EvtxFileCollector` (python-evtx), validated on EVTX-ATTACK-SAMPLES
- [x] `WindowsEventLogCollector` (XPath polling on EventRecordID + JSON state file)
- [x] `tinybrother scan file.evtx` (`--stats`, `--json`, `--limit`)
- [ ] Validate `tinybrother watch` on a real Windows host

## Milestone 2: Detection ✅
- [x] Sigma field modifiers (contains, startswith, endswith, all, cased, re, cidr, gt/lt,
      exists, fieldref, windash, base64, base64offset, wide/utf16) and wildcards
- [x] Condition parser (and / or / not / parentheses / `1 of` / `all of` / `them`)
- [x] Logsource → channel/EventID routing, Security 4688 ↔ Sysmon 1 field aliases
- [x] Full SigmaHQ Windows ruleset: 2,394 / 2,417 rules loaded, the rest reported with a reason
- [x] `tinybrother watch` stores alerts in SQLite, `tinybrother rules` shows coverage
- [x] Benchmark on EVTX-ATTACK-SAMPLES: 72% of recordings detected (`docs/benchmark.md`)

Possible improvements: field-presence pre-filter to skip rules faster, correlation /
aggregation rules (`count() by`), alert deduplication.

## Milestone 3: Dashboard
- [ ] `/api/alerts`, `/api/stats`, `/api/attack-coverage`
- [ ] Alert timeline, severity breakdown, event details
- [ ] ATT&CK coverage heatmap (rules loaded vs. techniques actually triggered)

## Milestone 4: Evaluation
- [ ] Windows VM lab + Atomic Red Team (see `docs/lab-setup.md`)
- [ ] Detection-rate report per ATT&CK tactic
- [ ] False-positive measurement on a normal workday

## Later
- Run as a Windows service, toast notifications
- Hash reputation enrichment (opt-in), anomaly detection
