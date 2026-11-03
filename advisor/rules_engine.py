"""
rules_engine.py - Smart Cleanup Rules Engine for Disk Space Advisor.

Loads and evaluates user-configurable rules from rules.json to match
candidate files and directories for safe cleanup.
"""

import os
import json
import fnmatch
import tempfile
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

from advisor.scanner import FileMetadata
from advisor.advisor import RiskLevel, is_protected_file

DEFAULT_RULES_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules.json")


def _get_active_rules_path(rules_path: str = DEFAULT_RULES_PATH) -> str:
    tmp_rules = os.path.join(tempfile.gettempdir(), "rules.json")
    if os.path.exists(tmp_rules):
        return tmp_rules
    return rules_path


@dataclass
class Rule:
    id: str
    name: str
    pattern: str               # comma-separated globs or dir names
    is_directory: bool
    min_age_days: int
    risk_level: str            # "SAFE", "REVIEW", "PROTECTED"
    explanation: str
    enabled: bool = True

    def get_patterns(self) -> List[str]:
        return [p.strip() for p in self.pattern.split(",") if p.strip()]


def load_rules(rules_path: str = DEFAULT_RULES_PATH) -> List[Rule]:
    """Loads cleanup rules from JSON file."""
    active_path = _get_active_rules_path(rules_path)
    if not os.path.exists(active_path):
        return []
    try:
        with open(active_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [Rule(**item) for item in data]
    except Exception:
        return []


def save_rules(rules: List[Rule], rules_path: str = DEFAULT_RULES_PATH) -> None:
    """Saves cleanup rules to JSON file."""
    data = [
        {
            "id": r.id,
            "name": r.name,
            "pattern": r.pattern,
            "is_directory": r.is_directory,
            "min_age_days": r.min_age_days,
            "risk_level": r.risk_level,
            "explanation": r.explanation,
            "enabled": r.enabled,
        }
        for r in rules
    ]
    target_path = rules_path
    if bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")) or not os.access(os.path.dirname(rules_path) or ".", os.W_OK):
        target_path = os.path.join(tempfile.gettempdir(), "rules.json")

    try:
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except OSError:
        pass


def match_file_against_rule(file_meta: FileMetadata, rule: Rule, now: float) -> bool:
    """Checks if a single file matches an active rule and meets its age requirement."""
    if not rule.enabled:
        return False

    # Check age threshold
    age_days = (now - file_meta.mtime) / 86400.0
    if age_days < rule.min_age_days:
        return False

    norm_path = os.path.normpath(file_meta.path)
    base_name = os.path.basename(norm_path)
    parts = norm_path.split(os.sep)

    for pat in rule.get_patterns():
        if rule.is_directory:
            # Check if any parent folder matches the directory pattern
            if pat in parts:
                return True
            if any(fnmatch.fnmatch(p.lower(), pat.lower()) for p in parts):
                return True
        else:
            # File pattern match on basename
            if fnmatch.fnmatch(base_name.lower(), pat.lower()):
                return True
            if fnmatch.fnmatch(norm_path.lower(), f"*/{pat.lower()}"):
                return True

    return False


def evaluate_rules_on_files(
    files: List[FileMetadata],
    rules: List[Rule],
    now: float
) -> Dict[str, Dict[str, Any]]:
    """
    Evaluates all rules on the file list and returns statistics:
    {
      rule_id: {
         "rule": Rule,
         "matched_count": int,
         "matched_bytes": int,
         "files": [FileMetadata, ...]
      }
    }
    """
    stats: Dict[str, Dict[str, Any]] = {
        r.id: {
            "id": r.id,
            "name": r.name,
            "pattern": r.pattern,
            "risk_level": r.risk_level,
            "explanation": r.explanation,
            "enabled": r.enabled,
            "matched_count": 0,
            "matched_bytes": 0,
            "matched_files": [],
        }
        for r in rules
    }

    for f in files:
        if f.is_hardlink_duplicate:
            continue
        # Never match protected files
        is_prot, _ = is_protected_file(f, now)
        if is_prot:
            continue

        for r in rules:
            if match_file_against_rule(f, r, now):
                s = stats[r.id]
                s["matched_count"] += 1
                s["matched_bytes"] += f.size
                s["matched_files"].append(f.path)
                break  # Attribute to first matching rule

    return stats
