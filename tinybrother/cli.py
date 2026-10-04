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
    watch.add_argument("--json", action="store_true", help="print events as JSON lines")

    scan = sub.add_parser("scan", help="analyse one or more .evtx files offline")
    scan.add_argument("files", nargs="+", help=".evtx files to scan")
    scan.add_argument("-n", "--limit", type=int, default=0, help="stop after N events")
    scan.add_argument("--json", action="store_true", help="print events as JSON lines")
    scan.add_argument("--stats", action="store_true", help="only print counts per EventID")

    sub.add_parser("dashboard", help="start the local web dashboard")
    sub.add_parser("rules", help="list loaded Sigma rules and ATT&CK coverage")
    return p


def cmd_scan(args: argparse.Namespace) -> int:
    from tinybrother.collectors.evtx_file import EvtxFileCollector
    from tinybrother.output import format_line, stats_table, to_json

    counter: Counter = Counter()
    total = errors = 0
    for path in args.files:
        collector = EvtxFileCollector(path)
        try:
            for event in collector.events():
                total += 1
                counter[(event.channel, event.event_id)] += 1
                if not args.stats:
                    print(to_json(event) if args.json else format_line(event))
                if args.limit and total >= args.limit:
                    break
        except FileNotFoundError:
            print(f"error: file not found: {path}", file=sys.stderr)
            return 2
        errors += collector.errors
        if args.limit and total >= args.limit:
            break

    if not args.json:
        print(f"\n{total} event(s), {errors} unreadable record(s)", file=sys.stderr)
        if args.stats:
            print(stats_table(counter))
    return 0


def cmd_watch(args: argparse.Namespace, cfg) -> int:
    from tinybrother.collectors.windows_eventlog import WindowsEventLogCollector
    from tinybrother.output import format_line, to_json

    if sys.platform != "win32":
        print("error: `watch` only works on Windows; use `scan` on .evtx files", file=sys.stderr)
        return 2
    state = cfg.database.parent / "state.json"
    collector = WindowsEventLogCollector(cfg.channels, state_file=state, from_start=args.from_start)
    try:
        for event in collector.events():
            print(to_json(event) if args.json else format_line(event), flush=True)
    except KeyboardInterrupt:
        print("\nstopped.", file=sys.stderr)
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
        return cmd_scan(args)
    if args.command == "dashboard":
        from tinybrother.dashboard.app import run

        run(cfg)
        return 0
    if args.command == "rules":
        raise NotImplementedError("rule listing: see docs/roadmap.md (milestone 2)")
    return 1
