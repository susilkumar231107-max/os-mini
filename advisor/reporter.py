"""
reporter.py - Output formatting and reporting for Cleanup Advisor.

Supports:
- Human-readable size formatting (B, KB, MB, GB, TB)
- Clean terminal tables and ASCII reports
- Exporting reports to TXT, CSV, and JSON
"""

import csv
import json
import time
from typing import List, Dict, Any, Optional

from advisor.scanner import ScanResult, FileMetadata
from advisor.analyzer import AnalysisResult
from advisor.advisor import CleanupProposal, RiskLevel


def format_bytes(size_bytes: int) -> str:
    """
    Converts raw byte count into human-readable representation (e.g. 10.5 MB, 1.2 GB).
    """
    if size_bytes < 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    val = float(size_bytes)
    unit_idx = 0
    while val >= 1024.0 and unit_idx < len(units) - 1:
        val /= 1024.0
        unit_idx += 1
    if unit_idx == 0:
        return f"{int(val)} B"
    return f"{val:.2f} {units[unit_idx]}"


def format_timestamp(epoch_seconds: float) -> str:
    """Formats epoch seconds into YYYY-MM-DD HH:MM:SS."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch_seconds))


def generate_terminal_report(
    scan_res: ScanResult,
    analysis: AnalysisResult,
    proposal: CleanupProposal,
    top_n: int = 10
) -> str:
    """
    Builds a structured terminal dashboard report summarizing:
    - Filesystem disk usage (total / used / free / % used)
    - Top large files
    - Stale files
    - Duplicate groups
    - Top directories by size
    - Recoverable space breakdown by category and total proposal
    """
    lines: List[str] = []
    sep = "=" * 80
    subsep = "-" * 80

    lines.append(sep)
    lines.append("        DISK SPACE AND LARGE-FILE CLEANUP ADVISOR (LINUX)")
    lines.append(sep)

    # 1. Disk Usage Summary
    used_pct = (scan_res.disk_used / scan_res.disk_total * 100) if scan_res.disk_total > 0 else 0.0
    lines.append(f"Target Path     : {scan_res.target_path}")
    lines.append(f"Disk Total      : {format_bytes(scan_res.disk_total)}")
    lines.append(f"Disk Used       : {format_bytes(scan_res.disk_used)} ({used_pct:.1f}%)")
    lines.append(f"Disk Free       : {format_bytes(scan_res.disk_free)}")
    lines.append(f"Scanned Files   : {scan_res.total_files_scanned} ({format_bytes(scan_res.total_bytes_scanned)})")
    if scan_res.unreadable_paths:
        lines.append(f"Unreadable Paths: {len(scan_res.unreadable_paths)} (permission/access errors skipped)")
    lines.append(subsep)

    # 2. Recoverable Space Estimation & Proposal Overview
    lines.append("PROPOSED CLEANUP & RECOVERABLE SPACE (NON-DESTRUCTIVE)")
    lines.append(subsep)
    lines.append(f"  [SAFE] Cleanable Space   : {format_bytes(proposal.safe_recoverable_bytes)}")
    for cat, sz in proposal.recoverable_by_category.items():
        lines.append(f"    - {cat.capitalize():<12}: {format_bytes(sz)}")
    lines.append(f"  [REVIEW] Potential Space : {format_bytes(proposal.review_recoverable_bytes)}")

    new_used = max(0, scan_res.disk_used - proposal.safe_recoverable_bytes)
    new_pct = (new_used / scan_res.disk_total * 100) if scan_res.disk_total > 0 else 0.0
    lines.append(f"  Estimated Usage After Safe Cleanup: {format_bytes(new_used)} ({new_pct:.1f}%)")
    lines.append(subsep)

    # 3. Top Large Files
    lines.append(f"TOP {min(top_n, len(analysis.large_files))} LARGE FILES")
    lines.append(subsep)
    if not analysis.large_files:
        lines.append("  No files exceeding threshold.")
    else:
        lines.append(f"  {'Size':<12} {'Owner':<10} {'Permissions':<12} {'Path'}")
        lines.append(f"  {'-'*10:<12} {'-'*8:<10} {'-'*11:<12} {'-'*40}")
        for f in analysis.large_files[:top_n]:
            lines.append(f"  {format_bytes(f.size):<12} {f.owner:<10} {f.permissions:<12} {f.path}")
    lines.append(subsep)

    # 4. Old / Stale Files
    lines.append(f"TOP {min(top_n, len(analysis.stale_files))} STALE FILES (BY LAST MODIFIED)")
    lines.append(subsep)
    if not analysis.stale_files:
        lines.append("  No files matching staleness criteria.")
    else:
        lines.append(f"  {'Size':<12} {'Modified':<20} {'Owner':<10} {'Path'}")
        lines.append(f"  {'-'*10:<12} {'-'*18:<20} {'-'*8:<10} {'-'*36}")
        for f in analysis.stale_files[:top_n]:
            mtime_str = format_timestamp(f.mtime)
            lines.append(f"  {format_bytes(f.size):<12} {mtime_str:<20} {f.owner:<10} {f.path}")
    lines.append(subsep)

    # 5. Duplicates Summary
    lines.append("DUPLICATE FILES (IDENTICAL SHA-256 HASH)")
    lines.append(subsep)
    if not analysis.duplicate_groups:
        lines.append("  No duplicate files detected.")
    else:
        lines.append(f"  Total Duplicate Groups: {len(analysis.duplicate_groups)}")
        lines.append(f"  Wasted Space in Dups  : {format_bytes(analysis.total_duplicate_wasted_bytes)}")
        for idx, g in enumerate(analysis.duplicate_groups[:top_n], start=1):
            lines.append(f"  Group #{idx} - Each: {format_bytes(g.size)} | Wasted: {format_bytes(g.wasted_space)}")
            lines.append(f"    [Original] {g.files[0]}")
            for dup_p in g.files[1:]:
                lines.append(f"    [Copy]     {dup_p}")
    lines.append(subsep)

    # 6. Top Directories by Size
    lines.append(f"TOP {len(analysis.directory_sizes)} LARGEST DIRECTORIES")
    lines.append(subsep)
    for dpath, dsize in analysis.directory_sizes:
        lines.append(f"  {format_bytes(dsize):<12} {dpath}")
    lines.append(sep)

    return "\n".join(lines)


def export_report(
    export_path: str,
    export_format: str,
    scan_res: ScanResult,
    analysis: AnalysisResult,
    proposal: CleanupProposal,
    top_n: int = 10
) -> None:
    """
    Exports scan & analysis results to TXT, CSV, or JSON.
    """
    fmt = export_format.lower()

    if fmt == "txt":
        content = generate_terminal_report(scan_res, analysis, proposal, top_n=top_n)
        with open(export_path, "w", encoding="utf-8") as f:
            f.write(content)

    elif fmt == "json":
        data = {
            "target_path": scan_res.target_path,
            "scan_timestamp": analysis.scan_timestamp,
            "disk_usage": {
                "total_bytes": scan_res.disk_total,
                "used_bytes": scan_res.disk_used,
                "free_bytes": scan_res.disk_free,
            },
            "scanned_metrics": {
                "total_files": scan_res.total_files_scanned,
                "total_bytes": scan_res.total_bytes_scanned,
                "unreadable_count": len(scan_res.unreadable_paths),
            },
            "recoverable_space": {
                "safe_bytes": proposal.safe_recoverable_bytes,
                "review_bytes": proposal.review_recoverable_bytes,
                "by_category": proposal.recoverable_by_category,
            },
            "top_large_files": [
                {
                    "path": f.path,
                    "size_bytes": f.size,
                    "size_human": format_bytes(f.size),
                    "owner": f.owner,
                    "permissions": f.permissions,
                    "mtime": f.mtime,
                }
                for f in analysis.large_files[:top_n]
            ],
            "stale_files": [
                {
                    "path": f.path,
                    "size_bytes": f.size,
                    "size_human": format_bytes(f.size),
                    "owner": f.owner,
                    "mtime": f.mtime,
                }
                for f in analysis.stale_files[:top_n]
            ],
            "duplicates": [
                {
                    "size_bytes": g.size,
                    "wasted_bytes": g.wasted_space,
                    "sha256": g.sha256,
                    "files": g.files,
                }
                for g in analysis.duplicate_groups[:top_n]
            ],
            "top_directories": [
                {"directory": dpath, "size_bytes": dsize, "size_human": format_bytes(dsize)}
                for dpath, dsize in analysis.directory_sizes
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    elif fmt == "csv":
        with open(export_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Section", "Path", "SizeBytes", "SizeHuman", "Risk", "Reason", "Category"])

            # Safe cleanup items
            for item in proposal.safe_items:
                writer.writerow(["SafeProposal", item.path, item.size, format_bytes(item.size), item.risk.value, item.reason, item.category])

            # Review cleanup items
            for item in proposal.review_items:
                writer.writerow(["ReviewProposal", item.path, item.size, format_bytes(item.size), item.risk.value, item.reason, item.category])

            # Large files
            for f_meta in analysis.large_files[:top_n]:
                writer.writerow(["LargeFiles", f_meta.path, f_meta.size, format_bytes(f_meta.size), "", "", ""])

            # Stale files
            for f_meta in analysis.stale_files[:top_n]:
                writer.writerow(["StaleFiles", f_meta.path, f_meta.size, format_bytes(f_meta.size), "", "", ""])
    else:
        raise ValueError(f"Unsupported export format '{fmt}'. Choose txt, csv, or json.")
