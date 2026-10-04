"""Command-line interface: `tinybrother watch | scan | dashboard | rules`."""

from __future__ import annotations

import argparse
import logging
import sys
from collections import Counter

from tinybrother import __version__
from tinybrother.config import load_config

BANNER = r"""
  _____ _             ___           _   _
 |_   _(_)_ _ _  _   | _ )_ _ ___ _| |_| |_  ___ _ _
   | | | | ' \ || |  | _ \ '_/ _ \  _| ' \/ -_) '_|
   |_| |_|_||_\_, |  |___/_| \___/\__|_||_\___|_|
              |__/        watching only you.
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tinybrother", description="A tiny personal SOC.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-c", "--config", default="config/tinybrother.yaml", help="config file")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    p.add_argument("-q", "--quiet", action="store_true", help="no banner")
    sub = p.add_subparsers(dest="command", required=True)

    watch = sub.add_parser("watch", help="collect and analyse live Windows events")
    watch.add_argument("--from-start", action="store_true",
                       help="first run: replay existing history instead of starting now")
    watch.add_argument("--json", action="store_true", help="print JSON lines")
    watch.add_argument("--events", action="store_true", help="print every event, not only alerts")

    scan = sub.add_parser("scan", help="analyse one or more .evtx files offline")
    scan.add_argument("files", nargs="+", help=".evtx files to scan")
    scan.add_argument("-n", "--limit", type=int, default=0, help="stop after N events")
    scan.add_argument("--json", action="store_true", help="print JSON lines")
    scan.add_argument("--events", action="store_true", help="print events instead of alerts")
    scan.add_argument("--stats", action="store_true", help="print counts instead of details")

    sub.add_parser("dashboard", help="start the local web dashboard")
    rules = sub.add_parser("rules", help="show loaded Sigma rules and ATT&CK coverage")
    rules.add_argument("--unsupported", action="store_true", help="list rules that were skipped")
    return p


def load_engine(cfg):
    from tinybrother.engine.engine import DetectionEngine

    engine = DetectionEngine.from_dirs(cfg.rule_dirs, min_level=cfg.min_severity)
    r = engine.report
    logging.getLogger("tinybrother").info(
        "%d Sigma rule(s) loaded, %d skipped (%.1fs)",
        r.loaded, len(r.unsupported) + len(r.parse_errors), r.seconds,
    )
    if r.loaded == 0:
        logging.getLogger("tinybrother").warning(
            "no rule loaded: run `python scripts/fetch_sigma_rules.py` from the project root"
        )
    return engine


def cmd_scan(args: argparse.Namespace, cfg) -> int:
    import glob
    from pathlib import Path

    from tinybrother.collectors.evtx_file import EvtxFileCollector
    from tinybrother.output import (
        alert_to_json,
        format_alert,
        format_line,
        stats_table,
        to_json,
    )

    # PowerShell/cmd do not expand wildcards for native programs: do it here
    files: list[str] = []
    for pattern in args.files:
        matches = sorted(glob.glob(pattern)) if glob.has_magic(pattern) else [pattern]
        if not matches or not all(Path(m).is_file() for m in matches):
            print(f"error: file not found: {pattern}", file=sys.stderr)
            return 2
        files.extend(matches)
    args.files = files
    engine = None if args.events else load_engine(cfg)
    counter: Counter = Counter()
    by_rule: Counter = Counter()
    total = errors = n_alerts = 0
    for path in args.files:
        collector = EvtxFileCollector(path)
        try:
            for event in collector.events():
                total += 1
                counter[(event.channel, event.event_id)] += 1
                if engine is None:
                    if not args.stats:
                        print(to_json(event) if args.json else format_line(event))
                else:
                    for alert in engine.evaluate(event):
                        n_alerts += 1
                        by_rule[(alert.severity.value, alert.rule_title)] += 1
                        if not args.stats:
                            print(alert_to_json(alert) if args.json else format_alert(alert))
                if args.limit and total >= args.limit:
                    break
        except FileNotFoundError:
            print(f"error: file not found: {path}", file=sys.stderr)
            return 2
        errors += collector.errors
        if args.limit and total >= args.limit:
            break

    if not args.json:
        msg = f"\n{total} event(s), {errors} unreadable record(s)"
        if engine is not None:
            msg += f", {n_alerts} alert(s)"
        print(msg, file=sys.stderr)
        if args.stats:
            print(stats_table(counter))
            if by_rule:
                print(f"\n{'severity':<14} {'hits':>5}  rule")
                print("-" * 70)
                for (sev, title), n in sorted(
                    by_rule.items(), key=lambda kv: (-_rank(kv[0][0]), -kv[1])
                ):
                    print(f"{sev:<14} {n:>5}  {title}")
    return 0


def _rank(level: str) -> int:
    from tinybrother.engine.engine import severity_rank

    return severity_rank(level)


def cmd_watch(args: argparse.Namespace, cfg) -> int:
    from tinybrother.collectors.windows_eventlog import WindowsEventLogCollector
    from tinybrother.output import alert_to_json, format_alert, format_line, to_json
    from tinybrother.storage.db import connect, save_alerts

    if sys.platform != "win32":
        print("error: `watch` only works on Windows; use `scan` on .evtx files", file=sys.stderr)
        return 2
    engine = load_engine(cfg)
    conn = connect(cfg.database)
    state = cfg.database.parent / "state.json"
    collector = WindowsEventLogCollector(cfg.channels, state_file=state, from_start=args.from_start)
    try:
        for event in collector.events():
            if args.events:
                print(to_json(event) if args.json else format_line(event), flush=True)
            alerts = engine.evaluate(event)
            if alerts:
                save_alerts(conn, alerts)
                for alert in alerts:
                    print(alert_to_json(alert) if args.json else format_alert(alert), flush=True)
    except KeyboardInterrupt:
        print("\nstopped.", file=sys.stderr)
    finally:
        conn.close()
    return 0


def cmd_rules(args: argparse.Namespace, cfg) -> int:
    from collections import Counter as C

    from tinybrother.attack.mapping import TACTICS, tactics_from_tags, techniques_from_tags

    engine = load_engine(cfg)
    r = engine.report
    print(f"loaded: {r.loaded}   unsupported: {len(r.unsupported)}   "
          f"unparsable: {len(r.parse_errors)}   load time: {r.seconds:.1f}s\n")

    levels = C(cr.severity.value for cr in engine.rules)
    print("by severity: " + "  ".join(f"{k}={levels[k]}" for k in
          ["critical", "high", "medium", "low", "informational"] if levels[k]))

    print(f"\n{'rules':>6}  channel")
    for ch, n in engine.rules_per_channel().most_common():
        print(f"{n:>6}  {ch}")

    tactics: C = C()
    techniques: set[str] = set()
    for cr in engine.rules:
        techniques.update(t.technique_id for t in techniques_from_tags(cr.rule.tags))
        for ta in tactics_from_tags(cr.rule.tags):
            tactics[ta] += 1
    print(f"\nATT&CK: {len(techniques)} distinct technique(s) covered")
    for ta in TACTICS:
        print(f"  {ta:<25} {tactics[ta]:>5} rule(s)")

    if r.unsupported:
        print("\nskipped rules by reason:")
        for reason, n in r.reasons().most_common(10):
            print(f"  {n:>5}  {reason}")
    if args.unsupported:
        print()
        for path, reason in r.unsupported + r.parse_errors:
            print(f"{path}: {reason}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )
    cfg = load_config(args.config)
    if not args.quiet and not getattr(args, "json", False):
        print(BANNER, file=sys.stderr)

    if args.command == "watch":
        return cmd_watch(args, cfg)
    if args.command == "scan":
        return cmd_scan(args, cfg)
    if args.command == "dashboard":
        from tinybrother.dashboard.app import run

        run(cfg)
        return 0
    if args.command == "rules":
        return cmd_rules(args, cfg)
    return 1
