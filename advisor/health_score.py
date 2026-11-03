"""
health_score.py - Disk Health Score and Recommendation Engine.

Computes a 0-100 composite score based on:
1. Disk Space Utilization (% of storage used)
2. Inode Utilization (via statvfs / df -i)
3. Stale & Inactive Data (% of scanned data untouched in > 180 days)
4. Redundant Duplicate Data (wasted space)
5. Cache & Scratch Space accumulation

Outputs:
- Numeric score (0-100)
- Rating: 'healthy' (green), 'warning' (amber), 'critical' (red)
- 3 plain-English actionable recommendations
- Critical alert flag if disk usage exceeds 80%
"""

import os
from typing import Dict, Any, List, Tuple
from advisor.scanner import ScanResult
from advisor.analyzer import AnalysisResult
from advisor.advisor import CleanupProposal
from advisor.reporter import format_bytes


def get_inode_utilization(path: str) -> Tuple[int, int, float]:
    """
    Retrieves inode count and utilization percentage using os.statvfs.
    Returns (total_inodes, free_inodes, used_percent).
    """
    try:
        st = os.statvfs(path)
        total_inodes = st.f_files
        free_inodes = st.f_ffree
        if total_inodes > 0:
            used_inodes = total_inodes - free_inodes
            used_pct = (used_inodes / total_inodes) * 100.0
            return total_inodes, free_inodes, round(used_pct, 1)
    except (OSError, AttributeError):
        pass
    return 0, 0, 0.0


def compute_disk_health(
    scan_res: ScanResult,
    analysis: AnalysisResult,
    proposal: CleanupProposal
) -> Dict[str, Any]:
    """
    Computes a comprehensive health assessment out of 100 points:
    - 40 pts: Disk space capacity (penalized heavily as used % approaches 100%)
    - 15 pts: Inode utilization (penalized if inodes > 80% used)
    - 15 pts: Stale file proportion (penalized if stale data > 30% of scanned bytes)
    - 15 pts: Duplicate wasted space (penalized if duplicate waste > 10% of scanned bytes)
    - 15 pts: Uncleaned caches & temporary clutter
    """
    # 1. Disk usage calculation
    disk_total = scan_res.disk_total
    disk_used = scan_res.disk_used
    used_pct = (disk_used / disk_total * 100.0) if disk_total > 0 else 0.0

    # Space score (40 pts)
    if used_pct < 60.0:
        space_score = 40.0
    elif used_pct < 80.0:
        space_score = 40.0 - ((used_pct - 60.0) / 20.0) * 15.0  # 40 down to 25
    elif used_pct < 90.0:
        space_score = 25.0 - ((used_pct - 80.0) / 10.0) * 15.0  # 25 down to 10
    else:
        space_score = max(0.0, 10.0 - ((used_pct - 90.0) / 10.0) * 10.0)

    # 2. Inode score (15 pts)
    _, _, inode_used_pct = get_inode_utilization(scan_res.target_path)
    if inode_used_pct < 70.0:
        inode_score = 15.0
    elif inode_used_pct < 90.0:
        inode_score = 15.0 - ((inode_used_pct - 70.0) / 20.0) * 10.0
    else:
        inode_score = max(0.0, 5.0 - ((inode_used_pct - 90.0) / 10.0) * 5.0)

    # 3. Stale data score (15 pts)
    scanned_bytes = max(1, scan_res.total_bytes_scanned)
    stale_bytes = sum(f.size for f in analysis.stale_files if not f.is_hardlink_duplicate)
    stale_pct = (stale_bytes / scanned_bytes) * 100.0
    if stale_pct < 15.0:
        stale_score = 15.0
    elif stale_pct < 40.0:
        stale_score = 15.0 - ((stale_pct - 15.0) / 25.0) * 8.0
    else:
        stale_score = max(2.0, 7.0 - ((stale_pct - 40.0) / 60.0) * 5.0)

    # 4. Duplicate score (15 pts)
    dup_wasted = analysis.total_duplicate_wasted_bytes
    dup_pct = (dup_wasted / scanned_bytes) * 100.0
    if dup_pct < 5.0:
        dup_score = 15.0
    elif dup_pct < 20.0:
        dup_score = 15.0 - ((dup_pct - 5.0) / 15.0) * 8.0
    else:
        dup_score = max(2.0, 7.0 - ((dup_pct - 20.0) / 40.0) * 5.0)

    # 5. Cache & temp score (15 pts)
    cache_temp_bytes = (
        proposal.recoverable_by_category.get("caches", 0) +
        proposal.recoverable_by_category.get("temp", 0) +
        proposal.recoverable_by_category.get("logs", 0)
    )
    cache_pct = (cache_temp_bytes / scanned_bytes) * 100.0
    if cache_pct < 10.0:
        cache_score = 15.0
    elif cache_pct < 30.0:
        cache_score = 15.0 - ((cache_pct - 10.0) / 20.0) * 7.0
    else:
        cache_score = max(2.0, 8.0 - ((cache_pct - 30.0) / 50.0) * 6.0)

    total_score = round(space_score + inode_score + stale_score + dup_score + cache_score)
    total_score = max(0, min(100, total_score))

    # Rating tier
    if total_score >= 80:
        status = "healthy"
        color = "#10b981"  # green
    elif total_score >= 55:
        status = "warning"
        color = "#f59e0b"  # amber
    else:
        status = "critical"
        color = "#ef4444"  # red

    # Plain-English recommendations
    recommendations: List[str] = []

    if used_pct >= 80.0:
        recommendations.append(
            f"Disk capacity is critically low at {used_pct:.1f}% used. Review and clear large stale files immediately."
        )
    elif used_pct >= 65.0:
        recommendations.append(
            f"Disk usage is at {used_pct:.1f}%. Safe candidate cleanup can recover {format_bytes(proposal.safe_recoverable_bytes)}."
        )
    else:
        recommendations.append("Filesystem disk space is comfortably within healthy operating thresholds.")

    if dup_wasted > 10 * 1024 * 1024:
        recommendations.append(
            f"Found {len(analysis.duplicate_groups)} duplicate groups wasting {format_bytes(dup_wasted)}. Remove redundant copies."
        )
    else:
        recommendations.append("Minimal duplicate file overhead detected; storage redundancy is low.")

    if cache_temp_bytes > 50 * 1024 * 1024:
        recommendations.append(
            f"Over {format_bytes(cache_temp_bytes)} of accumulated application caches and stale logs can be safely purged."
        )
    elif stale_bytes > 100 * 1024 * 1024:
        recommendations.append(
            f"Over {format_bytes(stale_bytes)} of files haven't been accessed in 180+ days. Consider archiving them to external storage."
        )
    else:
        recommendations.append("System temporary files and active caches are well maintained.")

    return {
        "score": total_score,
        "status": status,
        "color": color,
        "used_pct": round(used_pct, 1),
        "inode_used_pct": inode_used_pct,
        "alert_high_disk": used_pct >= 80.0,
        "recommendations": recommendations[:3],
        "breakdown": {
            "space_score": round(space_score, 1),
            "inode_score": round(inode_score, 1),
            "stale_score": round(stale_score, 1),
            "dup_score": round(dup_score, 1),
            "cache_score": round(cache_score, 1)
        }
    }
