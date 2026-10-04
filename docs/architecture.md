# Architecture

TinyBrother is a single Python process organised as a pipeline:

```
Collector -> Normalizer -> Sigma engine -> ATT&CK enrichment -> Storage -> Dashboard
```

## Components

**Collectors** (`tinybrother/collectors/`) produce raw events. `WindowsEventLogCollector`
subscribes to live channels with `EvtSubscribe` and keeps a bookmark per channel so no event
is lost or duplicated across restarts. `EvtxFileCollector` replays exported `.evtx` files,
which makes the whole pipeline testable on any OS and useful for forensics.

**Normalizer** (`tinybrother/normalizer/`) converts the Windows XML into an `Event`. Field names
are kept as Windows/Sysmon names because Sigma rules reference them directly.

**Sigma engine** (`tinybrother/engine/`) loads YAML rules once, indexes them by `logsource`
(product/category/service → channel + EventID), and evaluates only the relevant subset for
each event. The condition grammar is parsed into an AST once per rule.

| Sigma logsource | Windows source |
|---|---|
| `category: process_creation` | Sysmon EID 1 (or Security 4688) |
| `category: network_connection` | Sysmon EID 3 |
| `category: registry_*` | Sysmon EID 12/13/14 |
| `category: file_event` | Sysmon EID 11 |
| `category: ps_script` | PowerShell/Operational EID 4104 |
| `service: security` | Security channel |

**ATT&CK enrichment** (`tinybrother/attack/`) reads `attack.*` tags and, later, joins them with
the MITRE ATT&CK STIX bundle to add names and tactic ordering for the coverage heatmap.

**Storage** (`tinybrother/storage/`) is SQLite in WAL mode. Only events that trigger an alert are
stored in full by default, to keep the database small on a personal machine.

**Dashboard** (`tinybrother/dashboard/`) is FastAPI serving a JSON API and a static page, bound to
`127.0.0.1` only.

## Threat model (summary)

TinyBrother itself holds sensitive data and runs as administrator, so it is a target:

| Threat (STRIDE) | Mitigation |
|---|---|
| Info disclosure: dashboard reachable from the LAN | bind to 127.0.0.1, no remote mode by default |
| Tampering: attacker edits rules to blind detection | rules dir ACL limited to admins; rule hash logged at startup |
| Tampering: attacker clears logs | dedicated rule for EID 1102 / 104 (log cleared) |
| DoS: event flood exhausts CPU/disk | bounded queue, rate limiting, DB retention policy |
| Elevation: malicious Sigma YAML | `yaml.safe_load` only, regex timeouts |
