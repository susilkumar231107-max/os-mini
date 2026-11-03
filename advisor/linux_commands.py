"""
linux_commands.py - Generates equivalent real-world Linux command lines for learning/viva.
"""

import shlex
from typing import Dict, List, Any


def generate_equivalent_commands(
    target_path: str,
    min_size_mb: float = 100,
    older_than_days: int = 180,
    top_n: int = 10
) -> List[Dict[str, str]]:
    """
    Returns equivalent Linux shell commands mapping each feature of the advisor
    to classic POSIX/GNU coreutils (df, du, find, awk, sort, sha256sum).
    """
    q_path = shlex.quote(target_path)
    min_size_str = f"+{int(min_size_mb)}M" if min_size_mb >= 1 else f"+{int(min_size_mb * 1024)}k"

    return [
        {
            "title": "Check Filesystem Usage & Inodes",
            "concept": "statvfs system call, superblock inspection",
            "cmd": f"df -h -i {q_path}",
            "explanation": "Inspects mounted filesystem total, used, free space, and available inodes (-i)."
        },
        {
            "title": "Find Top Largest Directories",
            "concept": "Recursive directory space accumulation (du)",
            "cmd": f"du -xh -d 1 {q_path} 2>/dev/null | sort -hr | head -n {top_n + 1}",
            "explanation": "Summarizes direct subdirectory sizes on the same filesystem (-x), sorted descending by human sizes."
        },
        {
            "title": "Find Large Files Exceeding Threshold",
            "concept": "Inode st_size attribute filter via find",
            "cmd": f"find {q_path} -xdev -type f -size {min_size_str} -exec ls -lh {{}} + 2>/dev/null | awk '{{print $5, $9}}' | sort -hr",
            "explanation": f"Scans regular files with size greater than {min_size_mb} MB and lists sizes with full paths."
        },
        {
            "title": "Find Stale Files Inactive for N Days",
            "concept": "Inode st_mtime attribute filter",
            "cmd": f"find {q_path} -type f -mtime +{older_than_days} -exec ls -lh {{}} + 2>/dev/null | awk '{{print $6, $7, $8, $9}}'",
            "explanation": f"Locates files whose modification time is older than {older_than_days} days (+{older_than_days})."
        },
        {
            "title": "Detect Duplicate Files by Content Hash",
            "concept": "Multi-stage hashing pipeline using find, size bucketing, and sha256sum",
            "cmd": f"find {q_path} -type f -size +1k ! -empty -exec sha256sum {{}} + 2>/dev/null | sort | uniq -w 64 -D",
            "explanation": "Computes SHA-256 for non-empty files and displays only duplicate hash collisions side-by-side."
        },
        {
            "title": "Clean Caches & Thumbnails Safely (User Space)",
            "concept": "Safe cache eviction in ~/.cache",
            "cmd": f"find ~/.cache -type f -atime +30 -name '*.tmp' -delete",
            "explanation": "Demonstrates how package/application caches older than 30 days are purged in Linux."
        }
    ]
