"""
advisor.py - Safety Classification and Cleanup Proposal Generator.

SAFETY POLICY:
- This tool NEVER performs any deletion or mutation of files.
- Generates a structured proposal and a ready-to-review shell script (cleanup_proposal.sh)
  where every single removal command is explicitly commented out with '# rm'.
- The user must explicitly inspect, uncomment, and execute the generated script manually.

RISK LEVELS:
- SAFE:
  * Temporary files in /tmp or /var/tmp older than 3 days.
  * Application/package caches (~/.cache, /var/cache, npm, pip, __pycache__).
  * Old rotated log files (*.gz, *.1, *.old) or logs stale for > 30 days.
  * Duplicate files (keeping the primary/first copy, proposing cleanup for redundant copies).
- REVIEW:
  * Large old files in user directories (~/Downloads, ~/Documents, etc.) not accessed in > 90 days.
  * Old compressed archives (.tar.gz, .zip, .iso) not in system paths.
  * Large media files that are stale.
- PROTECTED:
  * Files in system directories (/bin, /sbin, /usr, /lib, /etc, /boot, /opt).
  * Files owned by 'root' or UID 0.
  * Hidden dotfiles/dotdirs (.bashrc, .ssh, .config, .git).
  * Recently modified or accessed files (within the last 7 days).
"""

import os
import shlex
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Set, Tuple

from advisor.scanner import FileMetadata
from advisor.analyzer import AnalysisResult, DuplicateGroup


class RiskLevel(Enum):
    SAFE = "SAFE"
    REVIEW = "REVIEW"
    PROTECTED = "PROTECTED"


@dataclass
class CleanupItem:
    """Represents a candidate file proposed for cleanup."""
    path: str
    size: int
    risk: RiskLevel
    reason: str
    category: str


@dataclass
class CleanupProposal:
    """Aggregated proposal with space estimations and candidate list."""
    target_path: str
    safe_items: List[CleanupItem] = field(default_factory=list)
    review_items: List[CleanupItem] = field(default_factory=list)
    protected_items: List[CleanupItem] = field(default_factory=list)
    
    # Recoverable space sums (bytes)
    safe_recoverable_bytes: int = 0
    review_recoverable_bytes: int = 0
    
    # Category breakdowns of recoverable space (SAFE items only)
    recoverable_by_category: Dict[str, int] = field(default_factory=dict)


# Critical system directory prefixes that are always PROTECTED
SYSTEM_DIR_PREFIXES: List[str] = [
    "/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/boot",
    "/opt", "/var/lib", "/System", "/Library"
]

# Sensitive configuration or version control directories to protect
PROTECTED_CONFIG_NAMES: Set[str] = {
    ".git", ".svn", ".ssh", ".gnupg", ".config", ".bashrc", ".zshrc", ".profile"
}


def is_protected_file(file_meta: FileMetadata, now: float) -> Tuple[bool, Optional[str]]:
    """
    Evaluates whether a file must be unconditionally PROTECTED.
    Returns (is_protected, reason).
    """
    path = file_meta.path
    norm_path = os.path.abspath(path)
    parts = norm_path.split(os.sep)

    # 1. System directory check
    for sys_prefix in SYSTEM_DIR_PREFIXES:
        if norm_path == sys_prefix or norm_path.startswith(sys_prefix + os.sep):
            return True, f"Located in protected system directory ({sys_prefix})"

    # 2. Root ownership check
    if file_meta.owner in ("root", "0") or getattr(file_meta, "uid", None) == 0:
        return True, "Owned by root / system administrator"

    # 3. Sensitive configuration/dotfile check
    for part in parts:
        if part in PROTECTED_CONFIG_NAMES or (part.startswith(".") and part in [".bashrc", ".zshrc", ".profile"]):
            return True, f"Located inside sensitive configuration path ({part})"

    # 4. Recently active check (modified or accessed within the last 7 days)
    seven_days_ago = now - (7 * 86400)
    if file_meta.mtime > seven_days_ago:
        return True, "Recently modified within the last 7 days"
    if file_meta.atime > seven_days_ago:
        return True, "Recently accessed within the last 7 days"

    return False, None


def classify_candidate(file_meta: FileMetadata, category: str, now: float) -> Tuple[RiskLevel, str]:
    """
    Determines the risk classification for a file.
    Returns (RiskLevel, explanation_string).
    """
    # Check absolute protection first
    protected, reason = is_protected_file(file_meta, now)
    if protected and reason:
        return RiskLevel.PROTECTED, reason

    path_lower = file_meta.path.lower()
    age_days = (now - file_meta.mtime) / 86400

    # 1. SAFE Checks
    # Temp files older than 3 days
    if category == "temp" or "/tmp/" in path_lower or "/var/tmp/" in path_lower:
        if age_days >= 3:
            return RiskLevel.SAFE, f"Temporary file stale for {int(age_days)} days"

    # Cache files older than 7 days
    if category == "caches" or ".cache" in path_lower:
        if age_days >= 7:
            return RiskLevel.SAFE, f"Cache file not modified for {int(age_days)} days"

    # Rotated or stale logs
    if category == "logs":
        if any(file_meta.path.endswith(ext) for ext in [".gz", ".1", ".old", ".bak"]) or age_days >= 30:
            return RiskLevel.SAFE, f"Old/rotated log file inactive for {int(age_days)} days"

    # 2. REVIEW Checks
    # User archives or downloads stale for > 90 days
    if category == "archives":
        if age_days >= 90:
            return RiskLevel.REVIEW, f"Old archive file ({int(age_days)} days stale)"
        return RiskLevel.REVIEW, "Archive file requiring user verification"

    # Large stale media
    if category == "media" and age_days >= 90:
        return RiskLevel.REVIEW, f"Large media file unused for {int(age_days)} days"

    # Large files (> 25MB) inactive for at least 7 days
    if file_meta.size >= 25 * 1024 * 1024 and age_days >= 7:
        return RiskLevel.REVIEW, f"Large file ({file_meta.size / (1024**2):.1f} MB) inactive for {int(age_days)} days"

    # General files older than 180 days in user space
    if age_days >= 180:
        return RiskLevel.REVIEW, f"Stale user file inactive for {int(age_days)} days"

    # If it meets none of the cleanup criteria, treat as PROTECTED
    return RiskLevel.PROTECTED, "Active user data"


def generate_cleanup_proposal(
    analysis_result: AnalysisResult,
    reference_time: Optional[float] = None
) -> CleanupProposal:
    """
    Builds a safety-first cleanup proposal based on analysis findings.
    
    Includes:
    - SAFE items: Caches, temp files, stale logs.
    - DUPLICATES: Proposed cleanup for copies 2..N (SAFE if copies are not protected).
    - REVIEW items: Old archives, large user files.
    - Accurately aggregates estimated recoverable space.
    """
    now = reference_time if reference_time is not None else time.time()
    proposal = CleanupProposal(target_path=analysis_result.target_path)
    
    seen_paths: Set[str] = set()

    # 1. Process candidate files from categories (caches, temp, logs, archives, large files)
    all_candidates: List[Tuple[FileMetadata, str]] = []
    
    for cat_name, summary in analysis_result.categories.items():
        for f in summary.files:
            all_candidates.append((f, cat_name))

    for f, cat in all_candidates:
        if f.path in seen_paths:
            continue

        risk, reason = classify_candidate(f, cat, now)
        item = CleanupItem(path=f.path, size=f.size, risk=risk, reason=reason, category=cat)
        seen_paths.add(f.path)

        if risk == RiskLevel.SAFE:
            proposal.safe_items.append(item)
            proposal.safe_recoverable_bytes += f.size
            proposal.recoverable_by_category[cat] = (
                proposal.recoverable_by_category.get(cat, 0) + f.size
            )
        elif risk == RiskLevel.REVIEW:
            proposal.review_items.append(item)
            proposal.review_recoverable_bytes += f.size
        else:
            proposal.protected_items.append(item)

    # 2. Process Duplicates (keep first file, propose redundant copies)
    for group in analysis_result.duplicate_groups:
        if len(group.files) > 1:
            primary_file = group.files[0]
            # Redundant copies: group.files[1:]
            for redundant_path in group.files[1:]:
                # If redundant path was already processed as SAFE, don't duplicate tally
                already_safe = any(item.path == redundant_path for item in proposal.safe_items)
                if already_safe:
                    continue

                # Check if redundant file is protected
                # Fabricate minimal metadata check
                norm_p = os.path.abspath(redundant_path)
                is_sys = any(norm_p.startswith(p + os.sep) for p in SYSTEM_DIR_PREFIXES)
                if is_sys:
                    continue

                item = CleanupItem(
                    path=redundant_path,
                    size=group.size,
                    risk=RiskLevel.SAFE,
                    reason=f"Duplicate content of: {primary_file}",
                    category="duplicates"
                )
                proposal.safe_items.append(item)
                proposal.safe_recoverable_bytes += group.size
                proposal.recoverable_by_category["duplicates"] = (
                    proposal.recoverable_by_category.get("duplicates", 0) + group.size
                )

    return proposal


def generate_shell_script(
    proposal: CleanupProposal,
    output_script_path: str = "cleanup_proposal.sh"
) -> str:
    """
    Generates a shell script listing cleanup commands.
    CRITICAL: Every removal command is commented out with '# rm'.
    No automatic deletion will ever occur without explicit user editing.
    """
    abs_output = os.path.abspath(output_script_path)
    
    lines = [
        "#!/usr/bin/env bash",
        "# ====================================================================",
        "# Disk Space and Large-File Cleanup Advisor - Safe Proposal Script",
        "#",
        "# SAFETY NOTICE:",
        "# 1. All deletion commands below are COMMENTED OUT by default.",
        "# 2. Inspect each line carefully before uncommenting.",
        "# 3. Run this script ONLY after you have verified the file paths.",
        "# ====================================================================",
        "",
        f"# Target Scanned: {proposal.target_path}",
        f"# Estimated SAFE Recoverable Space: {proposal.safe_recoverable_bytes} bytes",
        f"# Estimated REVIEW Recoverable Space: {proposal.review_recoverable_bytes} bytes",
        "",
        "set -euo pipefail",
        "",
        "# --------------------------------------------------------------------",
        "# SECTION 1: SAFE CANDIDATES (Caches, Stale Temp, Rotated Logs, Duplicates)",
        "# --------------------------------------------------------------------",
    ]

    if not proposal.safe_items:
        lines.append("# No safe cleanup candidates identified.")
    else:
        for item in proposal.safe_items:
            quoted_path = shlex.quote(item.path)
            lines.append(f"# [{item.category.upper()}] ({item.size} bytes) - {item.reason}")
            lines.append(f"# rm -f {quoted_path}")
            lines.append("")

    lines.extend([
        "# --------------------------------------------------------------------",
        "# SECTION 2: REVIEW CANDIDATES (Requires manual review before action)",
        "# --------------------------------------------------------------------",
    ])

    if not proposal.review_items:
        lines.append("# No review candidates identified.")
    else:
        for item in proposal.review_items:
            quoted_path = shlex.quote(item.path)
            lines.append(f"# [{item.category.upper()}] ({item.size} bytes) - {item.reason}")
            lines.append(f"# rm -i {quoted_path}")
            lines.append("")

    lines.append("# End of cleanup proposal.\n")

    content = "\n".join(lines)
    with open(abs_output, "w", encoding="utf-8") as f:
        f.write(content)

    return abs_output
