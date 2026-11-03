"""
history_manager.py - Persistent Snapshot & Trend Tracking for Cleanup Advisor.

Saves scan summaries in ./history/ and computes differential trends between scans.
"""

import os
import json
import time
import tempfile
from typing import List, Dict, Any, Optional

_root = os.path.dirname(os.path.dirname(__file__))
if bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")) or not os.access(_root, os.W_OK):
    HISTORY_DIR = os.path.join(tempfile.gettempdir(), "history")
else:
    HISTORY_DIR = os.path.join(_root, "history")


def ensure_history_dir():
    try:
        os.makedirs(HISTORY_DIR, exist_ok=True)
    except OSError:
        pass


def save_scan_snapshot(
    target_path: str,
    metrics: Dict[str, Any],
    disk_usage: Dict[str, Any],
    recoverable: Dict[str, Any],
    top_directories: List[Dict[str, Any]],
    health_score: Dict[str, Any]
) -> str:
    """Saves a timestamped scan snapshot JSON file."""
    ensure_history_dir()
    timestamp = int(time.time())
    snapshot_filename = f"scan_{timestamp}.json"
    snapshot_path = os.path.join(HISTORY_DIR, snapshot_filename)

    snapshot_data = {
        "timestamp": timestamp,
        "date_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)),
        "target_path": target_path,
        "metrics": metrics,
        "disk_usage": disk_usage,
        "recoverable": recoverable,
        "top_directories": top_directories,
        "health_score": health_score,
    }

    try:
        with open(snapshot_path, "w", encoding="utf-8") as f:
            json.dump(snapshot_data, f, indent=2)
    except OSError:
        pass

    return snapshot_path


def get_scan_history(limit: int = 30) -> List[Dict[str, Any]]:
    """Loads all saved scan snapshots, sorted chronologically ascending."""
    ensure_history_dir()
    snapshots: List[Dict[str, Any]] = []

    for fname in sorted(os.listdir(HISTORY_DIR)):
        if fname.startswith("scan_") and fname.endswith(".json"):
            fpath = os.path.join(HISTORY_DIR, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    snapshots.append(data)
            except (json.JSONDecodeError, OSError):
                continue

    # Return last N snapshots
    return snapshots[-limit:]


def compute_scan_diff(scan_a: Dict[str, Any], scan_b: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes storage growth and differences between two scans:
    scan_a (earlier) vs scan_b (later).
    """
    time_a = scan_a.get("timestamp", 0)
    time_b = scan_b.get("timestamp", 0)
    if time_a > time_b:
        scan_a, scan_b = scan_b, scan_a  # ensure chronological

    used_a = scan_a.get("disk_usage", {}).get("used_bytes", 0)
    used_b = scan_b.get("disk_usage", {}).get("used_bytes", 0)
    space_diff = used_b - used_a

    files_a = scan_a.get("metrics", {}).get("total_files", 0)
    files_b = scan_b.get("metrics", {}).get("total_files", 0)
    files_diff = files_b - files_a

    # Compare top directories growth
    dirs_a = {d["path"]: d["size_bytes"] for d in scan_a.get("top_directories", [])}
    dirs_b = {d["path"]: d["size_bytes"] for d in scan_b.get("top_directories", [])}

    all_dir_paths = set(dirs_a.keys()).union(set(dirs_b.keys()))
    dir_growths = []

    for p in all_dir_paths:
        sz_a = dirs_a.get(p, 0)
        sz_b = dirs_b.get(p, 0)
        diff = sz_b - sz_a
        dir_growths.append({
            "path": p,
            "old_size": sz_a,
            "new_size": sz_b,
            "growth_bytes": diff
        })

    # Sort by growth descending
    dir_growths.sort(key=lambda x: x["growth_bytes"], reverse=True)

    return {
        "earlier_scan": scan_a.get("date_str"),
        "later_scan": scan_b.get("date_str"),
        "used_space_growth_bytes": space_diff,
        "files_count_diff": files_diff,
        "directory_growth": dir_growths[:10]
    }
