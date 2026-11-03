#!/usr/bin/env python3
"""
main.py - CLI Entry point for Disk Space and Large-File Cleanup Advisor.

Command Line Options:
  --path          Target directory to scan (default: current directory)
  --min-size      Threshold for large files (e.g. 50M, 1G, 100M - default: 100M)
  --older-than    Age threshold in days for stale files (default: 180)
  --top           Number of top items to display (default: 10)
  --export        Export report format: txt, csv, or json
  --export-file   Destination file for export (e.g. report.json, report.csv)
  --exclude       Comma-separated list of paths to exclude
  --generate-script Path to save generated cleanup proposal shell script (default: cleanup_proposal.sh)
"""

import sys
import os
import argparse
import re
from typing import Set

from advisor.scanner import scan_directory, DEFAULT_EXCLUDE_PATHS
from advisor.analyzer import analyze_scan
from advisor.advisor import generate_cleanup_proposal, generate_shell_script
from advisor.reporter import generate_terminal_report, export_report


def parse_size_string(size_str: str) -> int:
    """
    Parses human-friendly size strings like '100M', '1.5G', '500K', '1024' into bytes.
    """
    size_str = size_str.strip().upper()
    match = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?B?)$", size_str)
    if not match:
        raise argparse.ArgumentTypeError(
            f"Invalid size '{size_str}'. Use formats like 100M, 1.5G, 500K, or 1048576."
        )

    number_str, unit = match.groups()
    val = float(number_str)
    unit = unit.rstrip("B")

    multipliers = {
        "": 1,
        "K": 1024,
        "M": 1024 * 1024,
        "G": 1024 * 1024 * 1024,
        "T": 1024 * 1024 * 1024 * 1024,
    }

    return int(val * multipliers.get(unit, 1))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cleanup-advisor",
        description="Disk Space and Large-File Cleanup Advisor for Linux (Read-Only & Safe Proposals)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--path",
        default=".",
        help="Target directory to scan",
    )
    parser.add_argument(
        "--min-size",
        default="100M",
        help="Size threshold for large files (e.g. 50M, 1G, 100M)",
    )
    parser.add_argument(
        "--older-than",
        type=int,
        default=180,
        help="Age threshold in days for stale/unmodified files",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of top large/stale files and directories to display",
    )
    parser.add_argument(
        "--export",
        choices=["txt", "csv", "json"],
        help="Export report format (txt, csv, or json)",
    )
    parser.add_argument(
        "--export-file",
        help="Output file path when --export is specified (defaults to report.<format>)",
    )
    parser.add_argument(
        "--exclude",
        help="Comma-separated paths to exclude from traversal in addition to default system paths",
    )
    parser.add_argument(
        "--generate-script",
        default="cleanup_proposal.sh",
        help="File path to generate the commented-out safe shell cleanup script",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # 1. Validate target directory
    target_dir = os.path.abspath(args.path)
    if not os.path.exists(target_dir):
        print(f"Error: Target path '{args.path}' does not exist.", file=sys.stderr)
        return 1

    # 2. Parse thresholds and exclusions
    try:
        min_size_bytes = parse_size_string(args.min_size)
    except argparse.ArgumentTypeError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1

    excludes: Set[str] = set(DEFAULT_EXCLUDE_PATHS)
    if args.exclude:
        user_excludes = [p.strip() for p in args.exclude.split(",") if p.strip()]
        for p in user_excludes:
            excludes.add(os.path.abspath(p))

    # 3. Traversal Phase
    print(f"[*] Scanning filesystem tree: {target_dir} ...", file=sys.stderr)
    scan_result = scan_directory(
        target_dir=target_dir,
        exclude_paths=excludes,
        track_hardlinks=True,
    )

    # 4. Analysis Phase
    print("[*] Analyzing file sizes, staleness, duplicates, and categories ...", file=sys.stderr)
    analysis = analyze_scan(
        scan_result=scan_result,
        min_size_bytes=min_size_bytes,
        min_age_days=args.older_than,
        find_duplicates=True,
        top_dirs_limit=args.top,
    )

    # 5. Advisor Phase (Safe Proposal)
    print("[*] Generating non-destructive cleanup recommendations ...", file=sys.stderr)
    proposal = generate_cleanup_proposal(analysis)

    # Generate shell proposal script (all 'rm' commands commented out)
    script_path = generate_shell_script(proposal, output_script_path=args.generate_script)

    # 6. Reporting Phase (Terminal Output)
    terminal_report = generate_terminal_report(
        scan_res=scan_result,
        analysis=analysis,
        proposal=proposal,
        top_n=args.top,
    )
    print(terminal_report)
    print(f"\n[+] Generated reviewable cleanup script: {script_path}")
    print("    (Note: All deletion commands are safely commented out for manual inspection.)")

    # 7. Optional File Export
    if args.export:
        default_filename = f"report.{args.export}"
        export_dest = args.export_file if args.export_file else default_filename
        export_report(
            export_path=export_dest,
            export_format=args.export,
            scan_res=scan_result,
            analysis=analysis,
            proposal=proposal,
            top_n=args.top,
        )
        print(f"[+] Report exported successfully to: {os.path.abspath(export_dest)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
