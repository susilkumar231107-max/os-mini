"""
analyzer.py - Data Analysis and Classification for Disk Cleanup Advisor.

Key Capabilities:
1. Threshold Filtering:
   - Identifies large files exceeding a byte threshold (default: 100 MB).
   - Identifies stale/old files not modified or accessed in N days (default: 180 days).
2. Category Grouping:
   - Classifies files into logs, caches, temp, archives, media, and other based on
     both directory patterns and file extensions.
3. High-Efficiency Duplicate Detection:
   - Step 1: Group files by exact byte size. Only files sharing the same size (> 0)
     are candidate duplicates (eliminates ~99% of hashing work).
   - Step 2: For candidates, hash a small prefix (e.g., first 4KB).
   - Step 3: Compute full SHA-256 in chunks (e.g., 64KB) only for items with matching prefixes.
4. Directory Space Aggregation:
   - Computes total cumulative disk size per directory and extracts the top 10 largest directories.
"""

import os
import time
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Set, Optional

from advisor.scanner import FileMetadata, ScanResult

# Common extensions and patterns for file categorization
CATEGORY_EXTENSIONS: Dict[str, Set[str]] = {
    "logs": {
        ".log", ".out", ".err", ".journal", ".audit"
    },
    "temp": {
        ".tmp", ".temp", ".swp", ".swo", "~", ".bak", ".old", ".part", ".crdownload"
    },
    "archives": {
        ".tar", ".gz", ".bz2", ".xz", ".zip", ".7z", ".rar", ".tgz", ".tbz2",
        ".iso", ".img", ".deb", ".rpm", ".pkg"
    },
    "media": {
        ".mp4", ".mkv", ".avi", ".mov", ".flv", ".wmv", ".webm",
        ".mp3", ".wav", ".flac", ".aac", ".ogg",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".raw", ".svg"
    },
    "caches": {
        ".cache", ".pyc", ".pyo", ".class"
    }
}

CATEGORY_DIR_PATTERNS: Dict[str, List[str]] = {
    "logs": ["/var/log", "log", "logs"],
    "caches": ["cache", "caches", ".cache", ".npm", ".pip", "__pycache__", ".gradle", ".m2"],
    "temp": ["/tmp", "/var/tmp", "tmp", "temp"],
}

HASH_CHUNK_SIZE = 64 * 1024  # 64 KB read buffer
PARTIAL_HASH_SIZE = 4 * 1024  # 4 KB preview buffer


@dataclass
class DuplicateGroup:
    """Represents a set of files with identical content."""
    size: int
    sha256: str
    files: List[str] = field(default_factory=list)
    file_items: List[FileMetadata] = field(default_factory=list)

    @property
    def wasted_space(self) -> int:
        """Wasted space is (count - 1) * file_size."""
        return max(0, len(self.files) - 1) * self.size


@dataclass
class CategorySummary:
    """Statistics for a particular category of files."""
    name: str
    file_count: int = 0
    total_bytes: int = 0
    files: List[FileMetadata] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Comprehensive analytical findings from scanned filesystem data."""
    target_path: str
    large_files: List[FileMetadata]
    stale_files: List[FileMetadata]
    categories: Dict[str, CategorySummary]
    duplicate_groups: List[DuplicateGroup]
    total_duplicate_wasted_bytes: int
    directory_sizes: List[Tuple[str, int]]  # Top directory sizes sorted descending
    scan_timestamp: float


def classify_file(file_meta: FileMetadata) -> str:
    """
    Categorizes a file into: 'logs', 'caches', 'temp', 'archives', 'media', or 'other'.
    Uses file extensions and directory location patterns.
    """
    path_lower = file_meta.path.lower()
    norm_path = os.path.normpath(path_lower)
    parts = norm_path.split(os.sep)

    # 1. Directory pattern matching
    for cat, dir_names in CATEGORY_DIR_PATTERNS.items():
        for d in dir_names:
            if d.startswith("/"):
                if norm_path.startswith(d):
                    return cat
            else:
                if d in parts:
                    return cat

    # 2. Extension matching
    base_name = os.path.basename(path_lower)
    _, ext = os.path.splitext(base_name)

    # Special check for compound extensions like .tar.gz
    for cat, extensions in CATEGORY_EXTENSIONS.items():
        if ext in extensions:
            return cat
        if any(base_name.endswith(comp_ext) for comp_ext in [".tar.gz", ".tar.bz2", ".tar.xz"]):
            return "archives"

    # Default fallback
    return "other"


def _compute_file_hash(path: str, max_bytes: Optional[int] = None) -> Optional[str]:
    """
    Computes SHA-256 hash of a file's content in chunks.
    If max_bytes is provided, reads only up to max_bytes (useful for fast initial pass).
    Returns None if file cannot be read due to permission or I/O errors.
    """
    hasher = hashlib.sha256()
    bytes_read = 0

    try:
        with open(path, "rb") as f:
            while True:
                to_read = HASH_CHUNK_SIZE
                if max_bytes is not None:
                    remaining = max_bytes - bytes_read
                    if remaining <= 0:
                        break
                    to_read = min(HASH_CHUNK_SIZE, remaining)

                chunk = f.read(to_read)
                if not chunk:
                    break
                hasher.update(chunk)
                bytes_read += len(chunk)

        return hasher.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def detect_duplicates(files: List[FileMetadata], min_size: int = 1) -> List[DuplicateGroup]:
    """
    Identifies duplicate files with minimum overhead:
    1. Filters out hard link duplicates (already share the same inode).
    2. Groups candidates by exact file size.
    3. Hashes a 4KB prefix for size collisions.
    4. Performs full SHA-256 hash only when prefix matches.
    """
    # Exclude hard link duplicates and files smaller than min_size
    valid_files = [f for f in files if not f.is_hardlink_duplicate and f.size >= min_size]

    # Step 1: Bucket by size
    size_map: Dict[int, List[FileMetadata]] = defaultdict(list)
    for f in valid_files:
        size_map[f.size].append(f)

    # Keep only buckets with 2 or more files
    size_candidates = {s: flist for s, flist in size_map.items() if len(flist) > 1}

    # Step 2: Partial prefix hash (4KB)
    partial_hash_map: Dict[Tuple[int, str], List[FileMetadata]] = defaultdict(list)
    for size, candidates in size_candidates.items():
        for f in candidates:
            p_hash = _compute_file_hash(f.path, max_bytes=PARTIAL_HASH_SIZE)
            if p_hash is not None:
                partial_hash_map[(size, p_hash)].append(f)

    # Filter out singletons
    partial_candidates = {k: flist for k, flist in partial_hash_map.items() if len(flist) > 1}

    # Step 3: Full SHA-256 hash on remaining candidates
    duplicate_groups: List[DuplicateGroup] = []
    full_hash_map: Dict[Tuple[int, str], List[FileMetadata]] = defaultdict(list)

    for (size, _), candidates in partial_candidates.items():
        for f in candidates:
            # If file size was <= PARTIAL_HASH_SIZE, prefix hash is already the full hash
            if size <= PARTIAL_HASH_SIZE:
                f_hash = _compute_file_hash(f.path, max_bytes=PARTIAL_HASH_SIZE)
            else:
                f_hash = _compute_file_hash(f.path)

            if f_hash is not None:
                full_hash_map[(size, f_hash)].append(f)

    for (size, f_hash), f_items in full_hash_map.items():
        if len(f_items) > 1:
            duplicate_groups.append(
                DuplicateGroup(
                    size=size,
                    sha256=f_hash,
                    files=[f.path for f in f_items],
                    file_items=f_items
                )
            )

    # Sort groups by wasted space descending
    duplicate_groups.sort(key=lambda g: g.wasted_space, reverse=True)
    return duplicate_groups


def compute_directory_sizes(files: List[FileMetadata], top_n: int = 10) -> List[Tuple[str, int]]:
    """
    Calculates the aggregated byte size of all files contained within each directory.
    Attribution is immediate parent directory.
    Returns the top N largest directories sorted by size descending.
    """
    dir_sizes: Dict[str, int] = defaultdict(int)

    for f in files:
        if not f.is_hardlink_duplicate:
            parent = os.path.dirname(f.path)
            dir_sizes[parent] += f.size

    # Sort descending
    sorted_dirs = sorted(dir_sizes.items(), key=lambda item: item[1], reverse=True)
    return sorted_dirs[:top_n]


def analyze_scan(
    scan_result: ScanResult,
    min_size_bytes: int = 100 * 1024 * 1024,  # 100 MB default
    min_age_days: int = 180,                 # 180 days default
    find_duplicates: bool = True,
    top_dirs_limit: int = 10,
    reference_time: Optional[float] = None
) -> AnalysisResult:
    """
    Runs full analysis suite on a ScanResult object.

    Args:
        scan_result: ScanResult from scanner.py
        min_size_bytes: Byte threshold to qualify as a 'large file'
        min_age_days: Day threshold to qualify as a 'stale file' (mtime & atime older than N days)
        find_duplicates: Whether to compute SHA-256 duplicate analysis
        top_dirs_limit: Number of top largest directories to report
        reference_time: Epoch timestamp to calculate age against (defaults to current time)
    """
    now = reference_time if reference_time is not None else time.time()
    age_cutoff_seconds = min_age_days * 86400  # 86,400 seconds in a day

    large_files: List[FileMetadata] = []
    stale_files: List[FileMetadata] = []

    # Initialize categories
    cat_names = ["logs", "caches", "temp", "archives", "media", "other"]
    categories: Dict[str, CategorySummary] = {
        name: CategorySummary(name=name) for name in cat_names
    }

    for f in scan_result.files:
        # Check size threshold
        if f.size >= min_size_bytes:
            large_files.append(f)

        # Check age threshold (both mtime and atime older than cutoff)
        file_age = now - f.mtime
        if file_age >= age_cutoff_seconds:
            stale_files.append(f)

        # Categorize
        cat = classify_file(f)
        c_summary = categories[cat]
        c_summary.file_count += 1
        c_summary.files.append(f)
        if not f.is_hardlink_duplicate:
            c_summary.total_bytes += f.size

    # Sort large files by size descending
    large_files.sort(key=lambda x: x.size, reverse=True)

    # Sort stale files by oldest mtime ascending (oldest first)
    stale_files.sort(key=lambda x: x.mtime)

    # Duplicate detection
    duplicate_groups: List[DuplicateGroup] = []
    total_wasted = 0
    if find_duplicates:
        duplicate_groups = detect_duplicates(scan_result.files)
        total_wasted = sum(g.wasted_space for g in duplicate_groups)

    # Directory aggregation
    top_dirs = compute_directory_sizes(scan_result.files, top_n=top_dirs_limit)

    return AnalysisResult(
        target_path=scan_result.target_path,
        large_files=large_files,
        stale_files=stale_files,
        categories=categories,
        duplicate_groups=duplicate_groups,
        total_duplicate_wasted_bytes=total_wasted,
        directory_sizes=top_dirs,
        scan_timestamp=now,
    )
