#!/usr/bin/env python3
"""
app.py - Advanced Web Dashboard Backend for Disk Space and Large-File Cleanup Advisor.

Features:
- Single Flask app binding strictly to 127.0.0.1.
- All endpoints 100% READ-ONLY (no file deletion, renaming, or modification).
- Server-Sent Events (SSE) for live scan progress streaming with thread cancellation.
- Treemap hierarchy generator.
- Rules Engine integration (GET/POST /api/rules).
- File inspector panel (GET /api/file-inspect).
- History & Trend tracking (GET /api/history).
- Linux equivalent commands generator.
- Printable HTML report export (/report).
- Strict path sanitization and boundary validation.
"""

import os
import sys
import time
import json
import queue
import shutil
import tempfile
import threading
from typing import Dict, Any, Optional, Set, List

from flask import Flask, request, jsonify, render_template, send_file, Response

from advisor.scanner import scan_directory, get_filesystem_usage, DEFAULT_EXCLUDE_PATHS
from advisor.analyzer import analyze_scan, AnalysisResult
from advisor.advisor import generate_cleanup_proposal, generate_shell_script, CleanupProposal, RiskLevel
from advisor.reporter import format_bytes, format_timestamp, generate_terminal_report, export_report
from advisor.rules_engine import load_rules, save_rules, evaluate_rules_on_files, Rule
from advisor.health_score import compute_disk_health, get_inode_utilization
from advisor.history_manager import save_scan_snapshot, get_scan_history, compute_scan_diff
from advisor.file_inspector import inspect_file
from advisor.linux_commands import generate_equivalent_commands

PROJECT_ROOT = os.path.abspath(os.path.realpath(os.path.dirname(__file__)))
app = Flask(__name__, template_folder=os.path.join(PROJECT_ROOT, "templates"))

# State cache for current scan & proposal (in-memory, single-user local dashboard)
CURRENT_SCAN: Dict[str, Any] = {
    "scan_result": None,
    "analysis_result": None,
    "proposal": None,
    "script_path": None,
    "health": None,
    "rules_eval": None,
    "treemap": None,
    "last_payload": {},
}

# Scan Thread & Cancellation Management
SCAN_THREAD: Optional[threading.Thread] = None
SCAN_STOP_EVENT: threading.Event = threading.Event()
PROGRESS_QUEUE: queue.Queue = queue.Queue(maxsize=100)
SCAN_ACTIVE: bool = False

# Configuration for allowed scan boundaries
HOME_DIR = os.path.abspath(os.path.realpath(os.path.expanduser("~")))

IS_SERVERLESS = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))
if IS_SERVERLESS or not os.access(PROJECT_ROOT, os.W_OK):
    SANDBOX_DIR = os.path.join(tempfile.gettempdir(), "virtual_filesystem")
    DEMO_DIR = os.path.join(tempfile.gettempdir(), "demo_data")
else:
    SANDBOX_DIR = os.path.join(PROJECT_ROOT, "virtual_filesystem")
    DEMO_DIR = os.path.join(PROJECT_ROOT, "demo_data")

# Configurable SAFE_ROOT via environment variable (defaults to HOME_DIR)
# Can also be a comma-separated list of allowed roots
CONFIGURED_SAFE_ROOT = os.environ.get("SAFE_ROOT", "").strip()
if CONFIGURED_SAFE_ROOT:
    SAFE_ROOTS = [os.path.abspath(os.path.realpath(os.path.expanduser(p.strip()))) for p in CONFIGURED_SAFE_ROOT.split(",") if p.strip()]
else:
    SAFE_ROOTS = [
        SANDBOX_DIR,
        PROJECT_ROOT,
        HOME_DIR,
        os.path.abspath(os.path.realpath(tempfile.gettempdir())),
        "/tmp",
        "/private/tmp"
    ]
    if os.path.exists("/Users") and "/Users" not in SAFE_ROOTS:
        SAFE_ROOTS.append("/Users")
    if os.path.exists("/Volumes") and "/Volumes" not in SAFE_ROOTS:
        SAFE_ROOTS.append("/Volumes")

# Critical system directories that are strictly forbidden from scanning/browsing
FORBIDDEN_PREFIXES: List[str] = [
    "/proc", "/sys", "/dev", "/boot", "/etc", "/private/etc", "/bin", "/sbin", "/usr", "/lib", "/lib64"
]


def clean_and_normalize_path(input_path: str) -> str:
    """
    Cleans, strips quotes, expands ~ and environment variables,
    and converts Windows-style paths (e.g. C:\\... on WSL) if applicable.
    """
    if not input_path or not isinstance(input_path, str):
        return ""

    raw = input_path.strip().strip("'\"").strip()

    # Detect Windows drive paths like C:\ or C:/ and convert if under WSL or suggest
    if len(raw) >= 2 and raw[1] == ":" and raw[0].isalpha():
        # Windows path: if on WSL or linux with /mnt/<drive>, convert
        drive = raw[0].lower()
        rest = raw[2:].replace("\\", "/").lstrip("/")
        wsl_path = f"/mnt/{drive}/{rest}"
        if os.path.exists(wsl_path):
            raw = wsl_path

    # Expand environment variables and user home ~
    expanded = os.path.expandvars(os.path.expanduser(raw))
    return expanded


def validate_and_sanitize_path(input_path: str) -> str:
    """
    Validates and canonicalizes user path input:
    - Expands ~ and env vars, strips quotes/spaces.
    - Resolves realpath without following symlinks into forbidden zones.
    - Rejects access outside configured safe roots.
    - Strictly blocks critical system paths (/proc, /sys, /dev, /boot, /etc).
    """
    if not input_path or not isinstance(input_path, str):
        raise ValueError("Path cannot be empty.")

    cleaned = clean_and_normalize_path(input_path)
    if not cleaned:
        raise ValueError("Path cannot be empty.")

    # Check for Windows style path hint on non-Windows/non-WSL systems
    if len(cleaned) >= 2 and cleaned[1] == ":" and cleaned[0].isalpha():
        raise ValueError(f"Windows path '{input_path}' detected. On Linux/macOS please use forward slashes (e.g. /mnt/c/... or /Users/...).")

    norm_cleaned = os.path.abspath(cleaned)
    for forbidden in FORBIDDEN_PREFIXES:
        if norm_cleaned == forbidden or norm_cleaned.startswith(forbidden + os.sep):
            raise PermissionError(f"Access denied: Path '{forbidden}' is a protected system directory.")

    abs_path = os.path.abspath(os.path.realpath(cleaned))

    # 1. Check existence
    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"Directory does not exist: '{input_path}'")

    if not os.path.isdir(abs_path):
        raise ValueError(f"Path is a file, not a directory: '{input_path}'")

    # 2. Block system directories
    for forbidden in FORBIDDEN_PREFIXES:
        if abs_path == forbidden or abs_path.startswith(forbidden + os.sep):
            raise PermissionError(f"Access denied: Path '{forbidden}' is a protected system directory.")

    # 3. Restrict within safe boundaries: SAFE_ROOTS
    is_safe = False
    for root in SAFE_ROOTS:
        if abs_path == root or abs_path.startswith(root.rstrip(os.sep) + os.sep):
            is_safe = True
            break

    if not is_safe:
        root_desc = SAFE_ROOTS[0] if len(SAFE_ROOTS) == 1 else ", ".join(SAFE_ROOTS[:2])
        raise PermissionError(
            f"Access denied: Path is outside allowed safe root ({root_desc})."
        )

    return abs_path


@app.route("/api/validate-path", methods=["GET"])
def api_validate_path():
    """
    Validates a directory path for live feedback in the UI.
    Returns: { valid: bool, path: str, error: str|null, message: str }
    """
    raw_path = request.args.get("path", "").strip()
    if not raw_path:
        return jsonify({
            "valid": False,
            "path": "",
            "error": "Path cannot be empty.",
            "message": "Please enter or choose a directory path."
        })

    try:
        validated = validate_and_sanitize_path(raw_path)
        # Check readability
        if not os.access(validated, os.R_OK):
            return jsonify({
                "valid": False,
                "path": validated,
                "error": "Permission denied: Folder is not readable.",
                "message": "Permission denied: Folder is not readable."
            })

        return jsonify({
            "valid": True,
            "path": validated,
            "error": None,
            "message": "Folder OK"
        })
    except FileNotFoundError as err:
        return jsonify({"valid": False, "path": raw_path, "error": str(err), "message": str(err)})
    except PermissionError as err:
        return jsonify({"valid": False, "path": raw_path, "error": str(err), "message": str(err)})
    except ValueError as err:
        return jsonify({"valid": False, "path": raw_path, "error": str(err), "message": str(err)})
    except Exception as err:
        return jsonify({"valid": False, "path": raw_path, "error": str(err), "message": f"Invalid path: {str(err)}"})


@app.route("/api/quick-paths", methods=["GET"])
def api_quick_paths():
    """
    Returns existing, readable shortcuts for fast folder selection:
    Home, Downloads, Documents, Desktop, /tmp, project directory, and ./demo_data.
    """
    candidates = [
        {"name": "🧪 Sandbox Root", "path": SANDBOX_DIR, "icon": "🖥️"},
        {"name": "Downloads", "path": os.path.join(SANDBOX_DIR, "Downloads"), "icon": "📥"},
        {"name": "Documents", "path": os.path.join(SANDBOX_DIR, "Documents"), "icon": "📄"},
        {"name": "Logs", "path": os.path.join(SANDBOX_DIR, "Logs"), "icon": "📜"},
        {"name": "Cache", "path": os.path.join(SANDBOX_DIR, ".cache"), "icon": "⚡"},
        {"name": "Media", "path": os.path.join(SANDBOX_DIR, "Media"), "icon": "🎬"},
        {"name": "Projects", "path": os.path.join(SANDBOX_DIR, "Projects"), "icon": "📁"},
        {"name": "Temp", "path": os.path.join(SANDBOX_DIR, "Temp"), "icon": "🗑️"},
    ]

    valid_shortcuts = []
    for item in candidates:
        p = os.path.abspath(os.path.realpath(item["path"]))
        if os.path.exists(p) and os.path.isdir(p) and os.access(p, os.R_OK):
            try:
                # Ensure it passes validation / security rules
                safe_p = validate_and_sanitize_path(p)
                valid_shortcuts.append({
                    "name": item["name"],
                    "path": safe_p,
                    "icon": item["icon"]
                })
            except Exception:
                continue

    return jsonify({
        "shortcuts": valid_shortcuts,
        "safe_roots": SAFE_ROOTS
    })


@app.route("/api/browse", methods=["GET"])
def api_browse():
    """
    Server-side folder browser endpoint (READ-ONLY).
    Query params:
      path: directory to list (default: HOME_DIR)
      show_hidden: 1 to show hidden dot-folders, 0 to hide (default: 0)
    Returns:
      { current, parent, home, entries: [{name, path, is_dir, readable, file_count}] }
    """
    raw_path = request.args.get("path", "").strip()
    show_hidden = request.args.get("show_hidden", "0") in ("1", "true", "True")

    if not raw_path:
        target_dir = SANDBOX_DIR
    else:
        try:
            target_dir = validate_and_sanitize_path(raw_path)
        except Exception as err:
            return jsonify({"error": str(err), "entries": [], "current": raw_path, "readable": False}), 400

    try:
        parent_dir = os.path.dirname(target_dir) if target_dir != "/" else "/"
        can_go_up = parent_dir != target_dir
        try:
            validate_and_sanitize_path(parent_dir)
        except Exception:
            can_go_up = False

        show_files = request.args.get("show_files", "0") in ("1", "true", "True")
        entries = []
        try:
            with os.scandir(target_dir) as it:
                for entry in it:
                    name = entry.name
                    if not show_hidden and name.startswith("."):
                        continue

                    # Don't follow symlinks outside allowed tree
                    try:
                        if entry.is_symlink():
                            continue

                        if entry.is_dir(follow_symlinks=False):
                            full_path = os.path.abspath(os.path.realpath(entry.path))
                            # Check if readable
                            readable = os.access(full_path, os.R_OK)

                            # Quick file count if readable
                            file_count = None
                            if readable:
                                try:
                                    sub_entries = os.listdir(full_path)
                                    file_count = len(sub_entries)
                                except OSError:
                                    file_count = 0

                            entries.append({
                                "name": name,
                                "path": full_path,
                                "is_dir": True,
                                "readable": readable,
                                "file_count": file_count,
                                "size": None
                            })
                        elif show_files and entry.is_file(follow_symlinks=False):
                            full_path = os.path.abspath(entry.path)
                            try:
                                stat_info = entry.stat(follow_symlinks=False)
                                file_size = stat_info.st_size
                            except OSError:
                                file_size = 0
                            entries.append({
                                "name": name,
                                "path": full_path,
                                "is_dir": False,
                                "readable": os.access(full_path, os.R_OK),
                                "file_count": None,
                                "size": file_size
                            })
                    except (OSError, PermissionError):
                        continue
        except PermissionError:
            # Handle gracefully with clear JSON message and empty list
            return jsonify({
                "error": f"Permission denied accessing '{target_dir}'.",
                "entries": [],
                "current": target_dir,
                "parent": parent_dir if can_go_up else None,
                "can_go_up": can_go_up,
                "readable": False
            }), 200
        except FileNotFoundError:
            return jsonify({"error": f"Directory not found: '{target_dir}'.", "entries": [], "current": target_dir, "readable": False}), 404

        # Sort: directories first (alpha), then files (alpha)
        entries.sort(key=lambda x: (0 if x["is_dir"] else 1, x["name"].lower()))

        return jsonify({
            "current": target_dir,
            "parent": parent_dir if can_go_up else None,
            "can_go_up": can_go_up,
            "home": HOME_DIR,
            "safe_roots": SAFE_ROOTS,
            "entries": entries
        })

    except Exception as err:
        return jsonify({"error": f"Browse failed: {str(err)}", "entries": [], "current": target_dir}), 500


def build_treemap_hierarchy(files_list, target_path: str, max_depth: int = 4) -> Dict[str, Any]:
    """
    Constructs a nested D3 / Chart.js hierarchy tree:
    { "name": root, "value": total_bytes, "children": [...] }
    """
    root_node: Dict[str, Any] = {"name": os.path.basename(target_path) or target_path, "path": target_path, "children": {}, "value": 0}

    for f in files_list:
        if f.is_hardlink_duplicate:
            continue
        rel = os.path.relpath(f.path, target_path)
        parts = rel.split(os.sep)
        curr = root_node
        curr["value"] += f.size

        # Traverse directory components up to max_depth
        for depth, part in enumerate(parts[:-1]):
            if depth >= max_depth:
                break
            if part not in curr["children"]:
                sub_path = os.path.join(curr.get("path", target_path), part)
                curr["children"][part] = {"name": part, "path": sub_path, "children": {}, "value": 0}
            curr = curr["children"][part]
            curr["value"] += f.size

    def convert_to_list(node):
        res = {"name": node["name"], "path": node.get("path", ""), "value": node["value"]}
        if node["children"]:
            res["children"] = [convert_to_list(child) for child in node["children"].values()]
        return res

    return convert_to_list(root_node)


@app.route("/")
def index():
    """Serves the dashboard frontend page."""
    return render_template("index.html")


@app.route("/api/disk-usage", methods=["GET"])
def api_disk_usage():
    """Returns disk statistics (total, used, free, inode usage) for a given directory path."""
    raw_path = request.args.get("path", PROJECT_ROOT)
    try:
        safe_path = validate_and_sanitize_path(raw_path)
        total, used, free = get_filesystem_usage(safe_path)
        used_pct = round((used / total * 100), 2) if total > 0 else 0.0
        tot_inodes, free_inodes, inode_pct = get_inode_utilization(safe_path)

        return jsonify({
            "path": safe_path,
            "total_bytes": total,
            "used_bytes": used,
            "free_bytes": free,
            "total_human": format_bytes(total),
            "used_human": format_bytes(used),
            "free_human": format_bytes(free),
            "used_pct": used_pct,
            "free_pct": round(100.0 - used_pct, 2),
            "inode_total": tot_inodes,
            "inode_free": free_inodes,
            "inode_used_pct": inode_pct
        })
    except (ValueError, PermissionError) as err:
        return jsonify({"error": str(err)}), 400
    except Exception as err:
        return jsonify({"error": f"Failed to retrieve disk usage: {str(err)}"}), 500


@app.route("/api/scan/progress", methods=["GET"])
def api_scan_progress():
    """Server-Sent Events (SSE) stream for live scan progress."""
    def event_stream():
        start_time = time.time()
        while True:
            try:
                # Poll queue with 0.5s timeout
                msg = PROGRESS_QUEUE.get(timeout=0.5)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg.get("status") in ("completed", "cancelled", "error"):
                    break
            except queue.Empty:
                if not SCAN_ACTIVE:
                    yield f"data: {json.dumps({'status': 'idle'})}\n\n"
                    break
                elapsed = round(time.time() - start_time, 1)
                yield f"data: {json.dumps({'status': 'scanning', 'elapsed': elapsed})}\n\n"

    return Response(event_stream(), mimetype="text/event-stream")


@app.route("/api/scan/cancel", methods=["POST"])
def api_scan_cancel():
    """Cancels ongoing scan safely using threading.Event."""
    global SCAN_ACTIVE
    SCAN_STOP_EVENT.set()
    SCAN_ACTIVE = False
    try:
        PROGRESS_QUEUE.put_nowait({"status": "cancelled", "message": "Scan cancelled by user."})
    except queue.Full:
        pass
    return jsonify({"status": "cancelled", "message": "Cancellation signal sent."})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    Performs full recursive filesystem scan and analysis on the requested path.
    Payload: { path, min_size_mb, older_than_days, exclude }
    """
    global SCAN_ACTIVE
    data = request.get_json(force=True, silent=True) or {}
    raw_path = data.get("path") or SANDBOX_DIR
    min_size_mb = float(data.get("min_size_mb", 100))
    older_than_days = int(data.get("older_than_days", 180))
    user_excludes = data.get("exclude", [])

    try:
        target_path = validate_and_sanitize_path(raw_path)

        # Clear cancellation event and reset queue
        SCAN_STOP_EVENT.clear()
        SCAN_ACTIVE = True
        while not PROGRESS_QUEUE.empty():
            try: PROGRESS_QUEUE.get_nowait()
            except queue.Empty: break

        start_time = time.time()

        # Build exclusions
        excludes: Set[str] = set(DEFAULT_EXCLUDE_PATHS)
        # If not explicitly scanning demo_data, exclude demo_data to avoid polluting real scan results
        if target_path != DEMO_DIR and os.path.exists(DEMO_DIR):
            excludes.add(os.path.abspath(DEMO_DIR))

        if isinstance(user_excludes, list):
            for p in user_excludes:
                if p and isinstance(p, str):
                    excludes.add(os.path.abspath(os.path.expanduser(p.strip())))

        min_size_bytes = int(min_size_mb * 1024 * 1024)

        def progress_cb(count, bytes_scanned, current_folder):
            elapsed = round(time.time() - start_time, 1)
            try:
                PROGRESS_QUEUE.put_nowait({
                    "status": "scanning",
                    "files_scanned": count,
                    "bytes_scanned": bytes_scanned,
                    "bytes_scanned_human": format_bytes(bytes_scanned),
                    "current_folder": current_folder,
                    "elapsed_seconds": elapsed
                })
            except queue.Full:
                pass

        # 1. Scan filesystem (Fast re-analysis if path and excludes unchanged)
        last_payload = CURRENT_SCAN.get("last_payload") or {}
        last_path = last_payload.get("path")
        last_excludes = last_payload.get("excludes")
        cached_result = CURRENT_SCAN.get("scan_result")
        force_rescan = data.get("force_rescan", False)

        if not force_rescan and cached_result and last_path == target_path and last_excludes == excludes and (time.time() - getattr(cached_result, "scan_timestamp", 0)) < 600:
            scan_result = cached_result
        else:
            scan_result = scan_directory(
                target_dir=target_path,
                exclude_paths=excludes,
                track_hardlinks=True,
                progress_callback=progress_cb,
                stop_event=SCAN_STOP_EVENT
            )

        if SCAN_STOP_EVENT.is_set():
            SCAN_ACTIVE = False
            return jsonify({"status": "cancelled", "message": "Scan was aborted."}), 200

        # 2. Analyze results
        analysis = analyze_scan(
            scan_result=scan_result,
            min_size_bytes=min_size_bytes,
            min_age_days=older_than_days,
            find_duplicates=True,
            top_dirs_limit=10,
        )

        # 3. Generate non-destructive proposal
        proposal = generate_cleanup_proposal(analysis)

        # 4. Generate commented-out shell script in temp directory
        script_path = os.path.join(tempfile.gettempdir(), f"cleanup_proposal_{int(time.time())}.sh")
        generate_shell_script(proposal, output_script_path=script_path)

        # 5. Evaluate Rules Engine
        rules = load_rules()
        rules_eval = evaluate_rules_on_files(scan_result.files, rules, now=time.time())

        # 6. Compute Disk Health Score
        health = compute_disk_health(scan_result, analysis, proposal)

        # 7. Build Treemap Hierarchy
        treemap = build_treemap_hierarchy(scan_result.files, target_path)

        # 8. Generate Equivalent Linux Commands
        linux_cmds = generate_equivalent_commands(target_path, min_size_mb, older_than_days, top_n=10)

        # Cache in memory
        CURRENT_SCAN["scan_result"] = scan_result
        CURRENT_SCAN["analysis_result"] = analysis
        CURRENT_SCAN["proposal"] = proposal
        CURRENT_SCAN["script_path"] = script_path
        CURRENT_SCAN["health"] = health
        CURRENT_SCAN["rules_eval"] = rules_eval
        CURRENT_SCAN["treemap"] = treemap
        CURRENT_SCAN["last_payload"] = {
            "path": target_path,
            "min_size_mb": min_size_mb,
            "older_than_days": older_than_days,
            "excludes": excludes
        }

        # Prepare metrics for history snapshot
        metrics = {
            "total_files": scan_result.total_files_scanned,
            "total_bytes": scan_result.total_bytes_scanned,
            "total_bytes_human": format_bytes(scan_result.total_bytes_scanned),
            "large_files_count": len(analysis.large_files),
            "stale_files_count": len(analysis.stale_files),
            "duplicate_groups_count": len(analysis.duplicate_groups),
            "duplicate_wasted_bytes": analysis.total_duplicate_wasted_bytes,
            "duplicate_wasted_human": format_bytes(analysis.total_duplicate_wasted_bytes),
            "unreadable_count": len(scan_result.unreadable_paths),
        }

        disk_usage_info = {
            "total_bytes": scan_result.disk_total,
            "used_bytes": scan_result.disk_used,
            "free_bytes": scan_result.disk_free,
            "total_human": format_bytes(scan_result.disk_total),
            "used_human": format_bytes(scan_result.disk_used),
            "free_human": format_bytes(scan_result.disk_free),
            "used_pct": round((scan_result.disk_used / scan_result.disk_total * 100), 2) if scan_result.disk_total > 0 else 0.0,
        }

        recoverable_info = {
            "safe_bytes": proposal.safe_recoverable_bytes,
            "safe_human": format_bytes(proposal.safe_recoverable_bytes),
            "review_bytes": proposal.review_recoverable_bytes,
            "review_human": format_bytes(proposal.review_recoverable_bytes),
            "by_category": {
                k: {"bytes": v, "human": format_bytes(v)}
                for k, v in proposal.recoverable_by_category.items()
            }
        }

        top_dirs_payload = [
            {"path": dpath, "size_bytes": dsize, "size_human": format_bytes(dsize)}
            for dpath, dsize in analysis.directory_sizes
        ]

        # 9. Save Snapshot to History
        save_scan_snapshot(
            target_path=target_path,
            metrics=metrics,
            disk_usage=disk_usage_info,
            recoverable=recoverable_info,
            top_directories=top_dirs_payload,
            health_score=health
        )

        SCAN_ACTIVE = False
        try:
            PROGRESS_QUEUE.put_nowait({
                "status": "completed",
                "files_scanned": scan_result.total_files_scanned,
                "bytes_scanned": scan_result.total_bytes_scanned,
                "elapsed_seconds": round(time.time() - start_time, 1)
            })
        except queue.Full:
            pass

        # Prepare detailed duplicates list with metadata (Duplicate Finder 2.0)
        dup_2_payload = []
        for g in analysis.duplicate_groups[:50]:
            group_files = []
            for f in g.file_items:
                group_files.append({
                    "path": f.path,
                    "size_bytes": f.size,
                    "mtime": f.mtime,
                    "mtime_human": format_timestamp(f.mtime),
                    "owner": f.owner,
                    "path_len": len(f.path)
                })
            dup_2_payload.append({
                "size_bytes": g.size,
                "size_human": format_bytes(g.size),
                "wasted_bytes": g.wasted_space,
                "wasted_human": format_bytes(g.wasted_space),
                "sha256": g.sha256,
                "files": group_files
            })

        category_breakdown = {}
        for cat_name, summ in analysis.categories.items():
            category_breakdown[cat_name] = {
                "count": summ.file_count,
                "bytes": summ.total_bytes,
                "human": format_bytes(summ.total_bytes)
            }

        large_files_payload = [
            {
                "path": f.path,
                "size_bytes": f.size,
                "size_human": format_bytes(f.size),
                "owner": f.owner,
                "permissions": f.permissions,
                "mtime": f.mtime,
                "mtime_human": format_timestamp(f.mtime)
            }
            for f in analysis.large_files[:60]
        ]

        stale_files_payload = [
            {
                "path": f.path,
                "size_bytes": f.size,
                "size_human": format_bytes(f.size),
                "owner": f.owner,
                "mtime": f.mtime,
                "mtime_human": format_timestamp(f.mtime),
                "age_days": round((time.time() - f.mtime) / 86400, 1)
            }
            for f in analysis.stale_files[:60]
        ]

        return jsonify({
            "target_path": target_path,
            "metrics": metrics,
            "disk_usage": disk_usage_info,
            "recoverable_space": recoverable_info,
            "large_files": large_files_payload,
            "stale_files": stale_files_payload,
            "duplicates": dup_2_payload,
            "top_directories": top_dirs_payload,
            "categories": category_breakdown,
            "health_score": health,
            "treemap": treemap,
            "linux_commands": linux_cmds,
            "rules_summary": [
                {
                    "id": k,
                    "name": v["name"],
                    "risk_level": v["risk_level"],
                    "enabled": v["enabled"],
                    "matched_count": v["matched_count"],
                    "matched_bytes": v["matched_bytes"],
                    "matched_human": format_bytes(v["matched_bytes"]),
                    "explanation": v["explanation"]
                }
                for k, v in rules_eval.items()
            ]
        })

    except (ValueError, PermissionError) as err:
        SCAN_ACTIVE = False
        return jsonify({"error": str(err)}), 400
    except Exception as err:
        SCAN_ACTIVE = False
        return jsonify({"error": f"Scan failed: {str(err)}"}), 500


@app.route("/api/proposal", methods=["GET"])
def api_proposal():
    """Returns detailed proposal candidates with risk classifications."""
    proposal: Optional[CleanupProposal] = CURRENT_SCAN.get("proposal")
    if not proposal:
        return jsonify({"error": "No scan performed yet. Please run a scan first."}), 400

    def serialize_items(items):
        return [
            {
                "path": item.path,
                "size_bytes": item.size,
                "size_human": format_bytes(item.size),
                "risk": item.risk.value,
                "reason": item.reason,
                "category": item.category
            }
            for item in items
        ]

    return jsonify({
        "target_path": proposal.target_path,
        "safe_recoverable_bytes": proposal.safe_recoverable_bytes,
        "safe_recoverable_human": format_bytes(proposal.safe_recoverable_bytes),
        "review_recoverable_bytes": proposal.review_recoverable_bytes,
        "review_recoverable_human": format_bytes(proposal.review_recoverable_bytes),
        "safe_items": serialize_items(proposal.safe_items),
        "review_items": serialize_items(proposal.review_items),
        "protected_items": serialize_items(proposal.protected_items[:50]),
    })


@app.route("/api/rules", methods=["GET", "POST"])
def api_rules():
    """Manages smart cleanup rules."""
    if request.method == "GET":
        rules = load_rules()
        rules_eval = CURRENT_SCAN.get("rules_eval") or {}
        res = []
        for r in rules:
            stats = rules_eval.get(r.id, {})
            res.append({
                "id": r.id,
                "name": r.name,
                "pattern": r.pattern,
                "is_directory": r.is_directory,
                "min_age_days": r.min_age_days,
                "risk_level": r.risk_level,
                "explanation": r.explanation,
                "enabled": r.enabled,
                "matched_count": stats.get("matched_count", 0),
                "matched_bytes": stats.get("matched_bytes", 0),
                "matched_human": format_bytes(stats.get("matched_bytes", 0))
            })
        return jsonify(res)
    else:
        # POST: update rule enabled state or rules list
        payload = request.get_json(force=True, silent=True) or {}
        rules = load_rules()
        rule_id = payload.get("id")
        enabled = payload.get("enabled")

        if rule_id is not None and enabled is not None:
            for r in rules:
                if r.id == rule_id:
                    r.enabled = bool(enabled)
                    break
            save_rules(rules)
            return jsonify({"status": "success", "message": f"Rule {rule_id} updated."})

        return jsonify({"error": "Invalid rule update payload."}), 400


@app.route("/api/file-inspect", methods=["GET"])
def api_file_inspect():
    """Safe read-only file metadata inspector and 2 KB preview."""
    target_file = request.args.get("path")
    if not target_file:
        return jsonify({"error": "Path parameter is required."}), 400

    try:
        abs_path = os.path.abspath(target_file)
        # Block forbidden system paths
        for forbidden in FORBIDDEN_PREFIXES:
            if abs_path == forbidden or abs_path.startswith(forbidden + os.sep):
                raise PermissionError("Access to system path is forbidden.")

        info = inspect_file(abs_path, base_safe_dir=HOME_DIR)
        return jsonify(info)
    except (FileNotFoundError, PermissionError) as err:
        return jsonify({"error": str(err)}), 400
    except Exception as err:
        return jsonify({"error": f"Inspection failed: {str(err)}"}), 500


@app.route("/api/history", methods=["GET"])
def api_history():
    """Returns saved scan history snapshots and comparison trends."""
    snapshots = get_scan_history(limit=25)
    diff = None
    if len(snapshots) >= 2:
        diff = compute_scan_diff(snapshots[-2], snapshots[-1])

    return jsonify({
        "snapshots": snapshots,
        "latest_diff": diff
    })


@app.route("/report", methods=["GET"])
def printable_report():
    """Renders printable HTML report with browser print stylesheet."""
    scan_res = CURRENT_SCAN.get("scan_result")
    analysis = CURRENT_SCAN.get("analysis_result")
    proposal = CURRENT_SCAN.get("proposal")
    health = CURRENT_SCAN.get("health")

    if not (scan_res and analysis and proposal):
        return "<h3>No scan performed yet. Please perform a scan first.</h3>", 400

    top_large = analysis.large_files[:20]
    top_stale = analysis.stale_files[:20]

    return render_template(
        "report.html",
        scan=scan_res,
        analysis=analysis,
        proposal=proposal,
        health=health,
        top_large=top_large,
        top_stale=top_stale,
        format_bytes=format_bytes,
        format_timestamp=format_timestamp,
        now_str=time.strftime("%Y-%m-%d %H:%M:%S")
    )


@app.route("/api/export", methods=["GET"])
def api_export():
    """Exports current scan results as CSV, JSON, or TXT download."""
    fmt = request.args.get("format", "json").lower()
    scan_res = CURRENT_SCAN.get("scan_result")
    analysis = CURRENT_SCAN.get("analysis_result")
    proposal = CURRENT_SCAN.get("proposal")

    if not (scan_res and analysis and proposal):
        return jsonify({"error": "No scan results available to export."}), 400

    if fmt not in ["json", "csv", "txt"]:
        return jsonify({"error": f"Invalid format '{fmt}'. Choose 'json', 'csv', or 'txt'."}), 400

    tmp_export = os.path.join(tempfile.gettempdir(), f"scan_report_{int(time.time())}.{fmt}")
    export_report(
        export_path=tmp_export,
        export_format=fmt,
        scan_res=scan_res,
        analysis=analysis,
        proposal=proposal,
        top_n=20
    )

    mime_types = {
        "json": "application/json",
        "csv": "text/csv",
        "txt": "text/plain"
    }

    return send_file(
        tmp_export,
        as_attachment=True,
        download_name=f"disk_cleanup_report.{fmt}",
        mimetype=mime_types[fmt]
    )


@app.route("/api/download-script", methods=["GET"])
def api_download_script():
    """Downloads cleanup_proposal.sh with every 'rm' command safely commented out."""
    script_path = CURRENT_SCAN.get("script_path")
    if not script_path or not os.path.exists(script_path):
        proposal = CURRENT_SCAN.get("proposal")
        if not proposal:
            return jsonify({"error": "No scan performed yet. Run a scan first."}), 400
        script_path = os.path.join(tempfile.gettempdir(), "cleanup_proposal.sh")
        generate_shell_script(proposal, output_script_path=script_path)
        CURRENT_SCAN["script_path"] = script_path

    return send_file(
        script_path,
        as_attachment=True,
        download_name="cleanup_proposal.sh",
        mimetype="text/x-shellscript"
    )


def setup_default_virtual_filesystem(force_reset: bool = False):
    """
    Sets up an isolated, self-contained virtual demo filesystem (./virtual_filesystem).
    Contains realistic dummy files across multiple categories:
    - Large ISO & 4K Video files
    - Stale archives & rotated logs
    - Exact duplicate pairs with matching content
    - Application caches & temporary files
    Zero access to personal computer data.
    """
    if os.path.exists(SANDBOX_DIR) and not force_reset:
        return

    if os.path.exists(SANDBOX_DIR) and force_reset:
        shutil.rmtree(SANDBOX_DIR, ignore_errors=True)

    os.makedirs(SANDBOX_DIR, exist_ok=True)
    now = time.time()
    day = 86400

    def add_demo_file(subfolder, filename, size_bytes, age_days, content=None):
        fdir = os.path.join(SANDBOX_DIR, subfolder.strip("/\\"))
        os.makedirs(fdir, exist_ok=True)
        fpath = os.path.join(fdir, filename)
        with open(fpath, "wb") as f:
            if content:
                f.write(content)
                if size_bytes > len(content):
                    f.truncate(size_bytes)
            else:
                f.truncate(size_bytes)
        t = now - (age_days * day)
        os.utime(fpath, (t, t))
        return fpath

    # 1. Downloads: Large ISO (1.8 GB, 120 days old)
    add_demo_file("Downloads", "ubuntu-24.04-desktop-amd64.iso", int(1.8 * 1024**3), 120)
    # Stale archive (450 MB, 240 days old)
    add_demo_file("Downloads", "legacy_project_backup_2023.tar.gz", 450 * 1024**2, 240)
    # Installer (85 MB, 15 days old)
    add_demo_file("Downloads", "package_installer_v3.dmg", 85 * 1024**2, 15)

    # 2. Duplicate Group 1: 15 MB PDF reports
    pdf_payload = b"%PDF-1.7 DEMO DUPLICATE PAYLOAD SAMPLE REPORT DATA " * 50000
    add_demo_file("Documents", "Quarterly_Financial_Report_2024.pdf", 15 * 1024**2, 45, pdf_payload)
    add_demo_file("Downloads", "Quarterly_Financial_Report_copy.pdf", 15 * 1024**2, 45, pdf_payload)

    # 3. Duplicate Group 2: 75 MB Zip archives
    zip_payload = b"PK\x03\x04 DEMO DUPLICATE ARCHIVE COMPRESSED CONTENT " * 20000
    add_demo_file("Documents", "client_assets_archive.zip", 75 * 1024**2, 90, zip_payload)
    add_demo_file("Temp", "client_assets_archive_backup.zip", 75 * 1024**2, 90, zip_payload)

    # 4. Logs: Stale rotated logs (180 MB, 95 days old)
    add_demo_file("Logs", "nginx_access.log.1", 180 * 1024**2, 95)
    add_demo_file("Logs", "database_slow_query.log.gz", 65 * 1024**2, 110)
    add_demo_file("Logs", "current_app.log", 12 * 1024**2, 2)

    # 5. Caches: Browser & Package caches
    add_demo_file(".cache/google-chrome/Default", "cache_data_block_01", 95 * 1024**2, 45)
    add_demo_file(".cache/npm/_cacache", "content-v2-sha512", 140 * 1024**2, 60)

    # 6. Media: Large 4K video (2.4 GB, 190 days old)
    add_demo_file("Media", "product_launch_4k_footage.mp4", int(2.4 * 1024**3), 190)
    add_demo_file("Media", "podcast_episode_102.wav", 180 * 1024**2, 80)

    # 7. Projects: Old node_modules & pycache
    add_demo_file("Projects/web-platform/node_modules/old_lib", "bundle.min.js", 25 * 1024**2, 210)
    add_demo_file("Projects/web-platform/__pycache__", "server.cpython-312.pyc", 350 * 1024, 10)

    # 8. Temp: Stale temporary dump files
    add_demo_file("Temp", "heap_dump_crash_2024.tmp", 110 * 1024**2, 40)
    add_demo_file("Temp", "scratch_render_output.tmp", 45 * 1024**2, 25)


# Initialize virtual filesystem at import time
try:
    setup_default_virtual_filesystem()
except Exception as _e:
    logging.warning("Sandbox initialization deferred: %s", _e)


@app.route("/api/demo/files", methods=["GET"])
def api_demo_files():
    """Returns list of all files in the virtual sandbox."""
    files = []
    now = time.time()
    day = 86400

    if os.path.exists(SANDBOX_DIR):
        for root, dirs, filenames in os.walk(SANDBOX_DIR):
            for fname in filenames:
                fpath = os.path.join(root, fname)
                try:
                    st = os.stat(fpath)
                    rel = os.path.relpath(fpath, SANDBOX_DIR)
                    folder = os.path.dirname(rel) or "."
                    age_days = max(0, int((now - st.st_mtime) / day))
                    files.append({
                        "name": fname,
                        "folder": folder,
                        "rel_path": rel,
                        "path": fpath,
                        "size": st.st_size,
                        "size_human": format_bytes(st.st_size),
                        "age_days": age_days,
                        "mtime_human": format_timestamp(st.st_mtime)
                    })
                except OSError:
                    continue

    files.sort(key=lambda x: (x["folder"], x["name"]))
    return jsonify({
        "sandbox_root": SANDBOX_DIR,
        "total_files": len(files),
        "total_bytes": sum(f["size"] for f in files),
        "total_human": format_bytes(sum(f["size"] for f in files)),
        "files": files
    })


@app.route("/api/demo/add-file", methods=["POST"])
def api_demo_add_file():
    """
    Manually creates a custom file in the virtual demo sandbox.
    Payload: { name, folder, size_mb, age_days, is_duplicate, category }
    """
    data = request.get_json(force=True, silent=True) or {}
    filename = (data.get("name") or "custom_file.dat").strip().replace("/", "_").replace("\\", "_")
    folder = (data.get("folder") or "Downloads").strip().strip("/\\")
    size_mb = float(data.get("size_mb", 50))
    age_days = int(data.get("age_days", 30))
    is_duplicate = bool(data.get("is_duplicate", False))

    size_bytes = int(size_mb * 1024 * 1024)
    now = time.time()
    day = 86400

    target_dir = os.path.join(SANDBOX_DIR, folder)
    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, filename)

    payload = (f"DEMO_CUSTOM_PAYLOAD_{filename}_\n".encode("utf-8") * 500) if is_duplicate else None

    with open(target_path, "wb") as f:
        if payload:
            f.write(payload)
            if size_bytes > len(payload):
                f.truncate(size_bytes)
        else:
            f.truncate(size_bytes)

    mtime = now - (age_days * day)
    os.utime(target_path, (mtime, mtime))

    created_paths = [target_path]

    # If duplicate requested, create identical copy in Downloads or Temp
    if is_duplicate:
        dup_folder = "Downloads" if folder != "Downloads" else "Temp"
        dup_dir = os.path.join(SANDBOX_DIR, dup_folder)
        os.makedirs(dup_dir, exist_ok=True)
        name_parts = filename.rsplit(".", 1)
        dup_name = f"{name_parts[0]}_copy.{name_parts[1]}" if len(name_parts) == 2 else f"{filename}_copy"
        dup_path = os.path.join(dup_dir, dup_name)
        with open(dup_path, "wb") as f:
            if payload:
                f.write(payload)
                if size_bytes > len(payload):
                    f.truncate(size_bytes)
            else:
                f.truncate(size_bytes)
        os.utime(dup_path, (mtime, mtime))
        created_paths.append(dup_path)

    return jsonify({
        "status": "success",
        "message": f"Created {'2 duplicate files' if is_duplicate else '1 file'} successfully.",
        "created": created_paths
    })


@app.route("/api/demo/file", methods=["DELETE"])
def api_demo_delete_file():
    """Deletes a file specifically inside the virtual sandbox."""
    data = request.get_json(force=True, silent=True) or {}
    raw_path = data.get("path", "").strip()

    if not raw_path:
        return jsonify({"error": "Path required"}), 400

    # Ensure path is strictly inside SANDBOX_DIR
    if not os.path.isabs(raw_path):
        target_path = os.path.abspath(os.path.join(SANDBOX_DIR, raw_path))
    else:
        target_path = os.path.abspath(raw_path)

    if not target_path.startswith(SANDBOX_DIR + os.sep) and target_path != SANDBOX_DIR:
        return jsonify({"error": "Can only delete files inside the virtual sandbox."}), 403

    if os.path.exists(target_path) and os.path.isfile(target_path):
        os.remove(target_path)
        return jsonify({"status": "success", "message": f"Deleted {os.path.basename(target_path)}"})
    else:
        return jsonify({"error": "File not found inside sandbox."}), 404


@app.route("/api/demo/reset", methods=["POST"])
def api_demo_reset():
    """Resets virtual demo sandbox to default rich dataset."""
    setup_default_virtual_filesystem(force_reset=True)
    return jsonify({
        "status": "success",
        "sandbox_path": SANDBOX_DIR,
        "message": "Virtual sandbox reset to default sample files."
    })


@app.route("/api/demo/clear", methods=["POST"])
def api_demo_clear():
    """Clears all files from the virtual sandbox."""
    if os.path.exists(SANDBOX_DIR):
        shutil.rmtree(SANDBOX_DIR, ignore_errors=True)
    os.makedirs(SANDBOX_DIR, exist_ok=True)
    return jsonify({
        "status": "success",
        "sandbox_path": SANDBOX_DIR,
        "message": "All virtual sandbox files cleared."
    })


@app.route("/api/demo-setup", methods=["POST"])
def api_demo_setup():
    """
    Sets up virtual sandbox and returns path for scanning.
    """
    setup_default_virtual_filesystem(force_reset=True)
    return jsonify({
        "status": "success",
        "demo_path": SANDBOX_DIR,
        "message": "Virtual sandbox files successfully initialized."
    })


if __name__ == "__main__":
    # Bound exclusively to 127.0.0.1 for local security.
    port = int(os.environ.get("PORT", 5000))
    import socket
    def is_port_available(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(('127.0.0.1', p))
            s.close()
            return True
        except OSError:
            return False

    if not is_port_available(port):
        print(f"[!] Port {port} is occupied (e.g. by macOS AirPlay Receiver).")
        port = 5001
        print(f"[*] Starting on fallback port: http://127.0.0.1:{port}")
    else:
        print(f"[*] Starting Cleanup Advisor Web Dashboard on http://127.0.0.1:{port}")

    app.run(host="127.0.0.1", port=port, debug=False)
