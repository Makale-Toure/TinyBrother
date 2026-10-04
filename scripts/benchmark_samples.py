"""Measure detection coverage on a folder of attack recordings (.evtx).

Designed for EVTX-ATTACK-SAMPLES (https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES),
whose sub-folders are ATT&CK tactics. A file counts as "detected" when at least one
alert of severity >= --min-level fires on it.

Usage:
    python scripts/benchmark_samples.py path/to/EVTX-ATTACK-SAMPLES --out docs/benchmark.md
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tinybrother.collectors.evtx_file import EvtxFileCollector
from tinybrother.engine.engine import DetectionEngine, severity_rank


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("samples", type=Path)
    p.add_argument("--rules", nargs="+", default=[str(ROOT / "rules/sigma"), str(ROOT / "rules/custom")])
    p.add_argument("--min-level", default="medium")
    p.add_argument("--out", type=Path, help="write a Markdown report here")
    p.add_argument("--json", type=Path, help="per-file results cache (enables resuming)")
    p.add_argument("--max-seconds", type=float, default=0,
                   help="stop after this many seconds; rerun with the same --json to resume")
    args = p.parse_args()

    engine = DetectionEngine.from_dirs(args.rules)
    print(f"{engine.report.loaded} rules loaded", file=sys.stderr)
    min_rank = severity_rank(args.min_level)

    files = sorted(args.samples.rglob("*.evtx"))
    per_file = []
    if args.json and args.json.exists():
        per_file = json.loads(args.json.read_text(encoding="utf-8"))
    done = {r["file"] for r in per_file}
    start = time.perf_counter()
    for i, f in enumerate(files, 1):
        rel = f.relative_to(args.samples)
        if str(rel) in done:
            continue
        if args.max_seconds and time.perf_counter() - start > args.max_seconds:
            print(f"time budget reached ({len(per_file)}/{len(files)} files); rerun to resume",
                  file=sys.stderr)
            if args.json:
                args.json.write_text(json.dumps(per_file, indent=1), encoding="utf-8")
            return 3
        t0 = time.perf_counter()
        tactic = rel.parts[0] if len(rel.parts) > 1 else "Other"
        events = 0
        rules_hit: Counter = Counter()
        col = EvtxFileCollector(f)
        try:
            for ev in col.events():
                events += 1
                for a in engine.evaluate(ev):
                    if severity_rank(a.severity.value) >= min_rank:
                        rules_hit[a.rule_title] += 1
        except Exception as exc:  # noqa: BLE001
            print(f"  ! {rel}: {exc}", file=sys.stderr)
        per_file.append({"file": str(rel), "tactic": tactic, "events": events,
                         "seconds": round(time.perf_counter() - t0, 3),
                         "detected": bool(rules_hit), "rules": dict(rules_hit)})
        if args.json:
            args.json.write_text(json.dumps(per_file, indent=1), encoding="utf-8")
        print(f"[{i}/{len(files)}] {'DETECTED' if rules_hit else 'missed  '} {rel}", file=sys.stderr)
    total_events = sum(r["events"] for r in per_file)
    elapsed = sum(r.get("seconds", 0) for r in per_file)

    by_tactic: dict[str, list[dict]] = defaultdict(list)
    for r in per_file:
        by_tactic[r["tactic"]].append(r)

    lines = [
        "# Detection benchmark: EVTX-ATTACK-SAMPLES",
        "",
        f"- Rules loaded: **{engine.report.loaded}** (SigmaHQ Windows + custom)",
        (
            f"- Recordings: **{len(per_file)}** files, **{total_events}** events, "
            f"processed in {elapsed:.0f}s ({total_events / max(elapsed, 1e-9):.0f} events/s)"
        ),
        f"- A file is *detected* when at least one rule of level >= `{args.min_level}` fires.",
        "",
        "| Tactic folder | Files | Detected | Rate |",
        "|---|---:|---:|---:|",
    ]
    tot_d = 0
    for tactic in sorted(by_tactic):
        rows = by_tactic[tactic]
        d = sum(r["detected"] for r in rows)
        tot_d += d
        lines.append(f"| {tactic} | {len(rows)} | {d} | {100 * d / len(rows):.0f}% |")
    lines.append(f"| **Total** | **{len(per_file)}** | **{tot_d}** | "
                 f"**{100 * tot_d / max(len(per_file), 1):.0f}%** |")

    top = Counter()
    for r in per_file:
        for rule in r["rules"]:
            top[rule] += 1
    lines += ["", "## Most frequent rules (number of files)", "", "| Rule | Files |", "|---|---:|"]
    lines += [f"| {rule} | {n} |" for rule, n in top.most_common(15)]

    missed = [r["file"] for r in per_file if not r["detected"]]
    lines += ["", f"## Missed recordings ({len(missed)})", ""]
    lines += [f"- `{m}`" for m in missed]

    report = "\n".join(lines) + "\n"
    if args.out:
        args.out.write_text(report, encoding="utf-8")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
