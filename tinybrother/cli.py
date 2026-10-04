"""Command-line interface: `tinybrother watch | scan | dashboard | rules`."""

from __future__ import annotations

import argparse

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
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("watch", help="collect and analyse live Windows events")

    scan = sub.add_parser("scan", help="analyse one or more .evtx files offline")
    scan.add_argument("files", nargs="+", help=".evtx files to scan")

    sub.add_parser("dashboard", help="start the local web dashboard")
    sub.add_parser("rules", help="list loaded Sigma rules and ATT&CK coverage")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = load_config(args.config)
    print(BANNER)

    if args.command == "watch":
        raise NotImplementedError("live collection: see docs/roadmap.md (milestone 1)")
    if args.command == "scan":
        raise NotImplementedError("offline .evtx scan: see docs/roadmap.md (milestone 1)")
    if args.command == "dashboard":
        from tinybrother.dashboard.app import run

        run(cfg)
        return 0
    if args.command == "rules":
        raise NotImplementedError("rule listing: see docs/roadmap.md (milestone 2)")
    return 1
