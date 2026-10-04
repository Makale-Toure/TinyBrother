# Roadmap

## Milestone 0: Scaffold ✅
Repository layout, packaging, CI, README, example rule.

## Milestone 1: Collection
- [ ] `normalizer.windows.from_xml` with unit tests on sample XML
- [ ] `EvtxFileCollector` (python-evtx)
- [ ] `WindowsEventLogCollector` with bookmarks
- [ ] `tinybrother scan file.evtx` prints events

## Milestone 2: Detection
- [ ] Sigma field modifiers and wildcards
- [ ] Condition parser (and / or / not / parentheses / `1 of` / `all of`)
- [ ] Logsource → channel/EventID routing
- [ ] Load the full SigmaHQ Windows ruleset without errors (report unsupported rules)
- [ ] `tinybrother watch` stores alerts in SQLite

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
