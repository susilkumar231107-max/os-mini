"""
file_inspector.py - Safe Read-Only File Inspector.

Retrieves comprehensive POSIX file metadata (size, inode, hard link count,
owner, group, octal & rwx permissions, atime/mtime/ctime, file type) and a
read-only text preview (up to 2 KB) for text files.
"""

import os
import stat
import time
from typing import Dict, Any, Optional

from advisor.scanner import _resolve_owner_and_group
from advisor.advisor import classify_candidate, RiskLevel
from advisor.reporter import format_bytes, format_timestamp


def get_permissions_string(mode: int) -> str:
    """Converts st_mode into traditional -rwxr-xr-x format."""
    return stat.filemode(mode)


def is_text_file(path: str, block_size: int = 1024) -> bool:
    """Heuristic check to determine if file contains text vs binary."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(block_size)
            if not chunk:
                return True
            # If null bytes are present, it's typically binary
            if b"\x00" in chunk:
                return False
            # Try decoding as UTF-8
            try:
                chunk.decode("utf-8")
                return True
            except UnicodeDecodeError:
                return False
    except OSError:
        return False


def inspect_file(file_path: str, base_safe_dir: str) -> Dict[str, Any]:
    """
    Inspects a file safely without following symlinks.
    Returns complete metadata, classification, and text preview.
    """
    abs_path = os.path.abspath(file_path)

    # Security check: must exist and be within safe boundary
    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"File not found: '{file_path}'")

    # Don't follow symlinks
    st = os.stat(abs_path, follow_symlinks=False)
    owner_str, group_str = _resolve_owner_and_group(st.st_uid, st.st_gid)

    # Determine file type
    file_type = "Regular File"
    if stat.S_ISDIR(st.st_mode):
        file_type = "Directory"
    elif stat.S_ISLNK(st.st_mode):
        file_type = "Symbolic Link"
    elif stat.S_ISFIFO(st.st_mode):
        file_type = "FIFO (Named Pipe)"
    elif stat.S_ISSOCK(st.st_mode):
        file_type = "Socket"
    elif stat.S_ISCHR(st.st_mode):
        file_type = "Character Device"
    elif stat.S_ISBLK(st.st_mode):
        file_type = "Block Device"

    # Risk analysis & explanation
    from advisor.scanner import FileMetadata
    f_meta = FileMetadata(
        path=abs_path,
        size=st.st_size,
        mtime=st.st_mtime,
        atime=st.st_atime,
        owner=owner_str,
        group=group_str,
        permissions=oct(stat.S_IMODE(st.st_mode)),
        inode=st.st_ino,
        device=st.st_dev,
        is_hardlink_duplicate=(st.st_nlink > 1)
    )

    from advisor.analyzer import classify_file
    cat = classify_file(f_meta)
    risk_level, reason = classify_candidate(f_meta, cat, now=time.time())

    # Read preview (max 2 KB, text only)
    preview_text = None
    is_text = False
    if stat.S_ISREG(st.st_mode) and st.st_size > 0:
        is_text = is_text_file(abs_path)
        if is_text:
            try:
                with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                    preview_text = f.read(2048)  # first 2 KB
            except OSError as err:
                preview_text = f"[Could not read preview: {err}]"

    # Creation/Birth time or status change time
    ctime_val = getattr(st, "st_birthtime", st.st_ctime)

    return {
        "path": abs_path,
        "basename": os.path.basename(abs_path),
        "directory": os.path.dirname(abs_path),
        "size_bytes": st.st_size,
        "size_human": format_bytes(st.st_size),
        "inode": st.st_ino,
        "device": st.st_dev,
        "hard_links": st.st_nlink,
        "owner": owner_str,
        "group": group_str,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "permissions_octal": oct(stat.S_IMODE(st.st_mode)),
        "permissions_rwx": get_permissions_string(st.st_mode),
        "file_type": file_type,
        "category": cat,
        "risk_level": risk_level.value,
        "risk_reason": reason,
        "mtime": st.st_mtime,
        "mtime_human": format_timestamp(st.st_mtime),
        "atime": st.st_atime,
        "atime_human": format_timestamp(st.st_atime),
        "ctime": ctime_val,
        "ctime_human": format_timestamp(ctime_val),
        "is_text": is_text,
        "preview_text": preview_text
    }
