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

## Milestone 3: Dashboard ✅
- [x] JSON API: `/api/stats`, `/api/alerts` (filters, search, paging), `/api/alerts/{id}`,
      `/api/attack`, interactive docs at `/api/docs`
- [x] KPI tiles, stacked severity timeline, severity breakdown, top rules
- [x] ATT&CK heatmap: techniques covered by rules vs. triggered, click to filter
- [x] Alert drawer with full event fields and triage (new / acknowledged / closed / false positive)
- [x] Light and dark themes, auto-refresh, `scan --store` to explore recordings
- [x] Hardening: localhost only, Host header allow-list, JSON-only writes, XSS-safe rendering

## Milestone 4: Evaluation
- [ ] Windows VM lab + Atomic Red Team (see `docs/lab-setup.md`)
- [ ] Detection-rate report per ATT&CK tactic
- [ ] False-positive measurement on a normal workday

## Later
- Run as a Windows service, toast notifications
- Hash reputation enrichment (opt-in), anomaly detection
