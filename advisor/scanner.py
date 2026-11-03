"""
scanner.py - Filesystem Scanner for Disk Space and Cleanup Advisor.

OS CONCEPTS EXPLAINED:
1. Inodes (Index Nodes):
   - In Unix/Linux filesystems (like ext4, xfs, apfs), a file's name and directory
     location are decoupled from its metadata and actual disk blocks.
   - The inode stores file metadata: file type, permissions, ownership (UID/GID),
     file size, timestamps, and pointers to disk blocks.
   - Hard links: Multiple directory entries (filenames/paths) can point to the same
     inode on the same filesystem device (st_dev, st_ino). To prevent double-counting
     actual disk consumption, we track visited (st_dev, st_ino) pairs and only tally
     file size once per unique inode.

2. Directory Traversal and File Tree Walk:
   - A directory in Linux is simply a special file containing a list of filename-to-inode
     mappings (directory entries).
   - os.scandir() yields DirEntry objects which retrieve cached stat information from
     the underlying readdir() / getdents() system calls, significantly outperforming
     older stat()-per-file approaches.
   - Symlinks (Symbolic Links): Pointers containing a pathname string to another file
     or directory. Traversing symlinks can cause infinite recursion loops (e.g. cyclic links)
     and lead to unintentional traversal across unrelated directories or mounts. We explicitly
     refrain from following symlinks.

3. File Metadata & Timestamps:
   - st_size: Number of bytes in the file.
   - st_mtime (Modification Time): Timestamp when file content was last altered.
   - st_atime (Access Time): Timestamp when file was last read. Note that many modern
     Linux installations mount filesystems with 'relatime' or 'noatime' for performance,
     so atime is updated lazily or not at all.
   - st_mode & Permissions: Contains file type bits and Unix permission bits (read/write/execute
     for user, group, others).
   - Ownership: st_uid and st_gid identify the user and group owning the file. Standard
     library 'pwd' and 'grp' modules map these numeric IDs to human-readable names.
"""

import os
import stat
import shutil
import logging
from dataclasses import dataclass
from typing import Set, Tuple, List, Optional, Dict, Any

# Configure module-level logger
logger = logging.getLogger("cleanup_advisor.scanner")

# Default critical Linux / Unix system paths that should be skipped during scans
DEFAULT_EXCLUDE_PATHS: Set[str] = {
    "/proc",   # Virtual process information filesystem (procfs)
    "/sys",    # Virtual sysfs filesystem exposing kernel objects
    "/dev",    # Device files (udev / devtmpfs)
    "/boot",   # Critical bootloader files and kernel images
    "/etc",    # System configuration files
}

# Inode identifier across filesystems: (device_id, inode_number)
InodeKey = Tuple[int, int]


@dataclass
class FileMetadata:
    """
    Encapsulates core POSIX file metadata.
    """
    path: str
    size: int               # Size in bytes (st_size)
    mtime: float            # Last modification time (epoch seconds)
    atime: float            # Last access time (epoch seconds)
    owner: str              # Username or numeric UID string
    group: str              # Group name or numeric GID string
    permissions: str        # Octal permission string (e.g., '0644')
    inode: int              # Inode number (st_ino)
    device: int             # Device identifier (st_dev)
    is_hardlink_duplicate: bool = False  # True if inode was already seen


@dataclass
class ScanResult:
    """
    Summary and collection of files discovered during the scan.
    """
    target_path: str
    files: List[FileMetadata]
    unreadable_paths: List[str]
    total_files_scanned: int
    total_bytes_scanned: int
    disk_total: int
    disk_used: int
    disk_free: int


def _resolve_owner_and_group(uid: int, gid: int) -> Tuple[str, str]:
    """
    Resolves UID and GID to human-readable names using pwd/grp modules if available.
    Falls back gracefully to string representations of numbers on non-POSIX or error.
    """
    owner_str = str(uid)
    group_str = str(gid)

    try:
        import pwd
        owner_str = pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError, OverflowError):
        pass

    try:
        import grp
        group_str = grp.getgrgid(gid).gr_name
    except (KeyError, ImportError, OverflowError):
        pass

    return owner_str, group_str


def get_filesystem_usage(path: str) -> Tuple[int, int, int]:
    """
    Wraps shutil.disk_usage to return total, used, and free bytes for the filesystem
    containing the specified path (uses statvfs system call on Unix).
    """
    try:
        usage = shutil.disk_usage(path)
        return usage.total, usage.used, usage.free
    except OSError as err:
        logger.warning(f"Could not retrieve disk usage for '{path}': {err}")
        return 0, 0, 0


def scan_directory(
    target_dir: str,
    exclude_paths: Optional[Set[str]] = None,
    track_hardlinks: bool = True,
    progress_callback: Optional[Any] = None,
    stop_event: Optional[Any] = None
) -> ScanResult:
    """
    Recursively traverses `target_dir` collecting metadata for every regular file.

    Features:
    - Never follows symlinks (follow_symlinks=False).
    - Tracks (st_dev, st_ino) to ensure hard links are counted only once in total space.
    - Catches PermissionError and OSError gracefully, logging unreadable paths.
    - Skips paths matching `exclude_paths`.
    - Live progress callbacks & safe stop_event cancellation.
    """
    abs_target = os.path.abspath(target_dir)

    # Normalize exclude paths to canonical absolute paths
    raw_excludes = exclude_paths if exclude_paths is not None else DEFAULT_EXCLUDE_PATHS
    normalized_excludes: Set[str] = {
        os.path.abspath(p).rstrip(os.sep) for p in raw_excludes
    }

    visited_inodes: Set[InodeKey] = set()
    files_list: List[FileMetadata] = []
    unreadable_paths: List[str] = []

    total_files_scanned = 0
    total_bytes_scanned = 0

    # Retrieve overall filesystem stats
    disk_total, disk_used, disk_free = get_filesystem_usage(abs_target)

    # Stack for iterative traversal (avoids recursion depth limit on deep directory trees)
    dir_stack: List[str] = [abs_target]

    while dir_stack:
        if stop_event is not None and stop_event.is_set():
            logger.info("Scan stopped early by stop_event cancellation request.")
            break

        current_dir = dir_stack.pop()

        # Check exclusion rules
        norm_current = current_dir.rstrip(os.sep)
        if norm_current in normalized_excludes:
            logger.info(f"Skipping excluded directory: {current_dir}")
            continue

        try:
            # os.scandir provides an iterator of DirEntry objects
            # Using scandir is significantly faster than os.listdir + os.stat
            with os.scandir(current_dir) as entries:
                for entry in entries:
                    try:
                        # Don't follow symlinks
                        # is_symlink() checks if the directory entry itself is a symbolic link
                        if entry.is_symlink():
                            continue

                        # Check if it's a sub-directory to traverse
                        if entry.is_dir(follow_symlinks=False):
                            sub_dir_path = entry.path
                            sub_dir_norm = os.path.abspath(sub_dir_path).rstrip(os.sep)
                            if sub_dir_norm in normalized_excludes:
                                logger.info(f"Skipping excluded directory: {sub_dir_path}")
                                continue
                            dir_stack.append(sub_dir_path)

                        # Process regular files
                        elif entry.is_file(follow_symlinks=False):
                            # Obtain file attributes via stat(follow_symlinks=False)
                            st = entry.stat(follow_symlinks=False)

                            # Extract inode and device ID
                            inode_key: InodeKey = (st.st_dev, st.st_ino)
                            is_duplicate = False

                            if track_hardlinks:
                                if inode_key in visited_inodes:
                                    is_duplicate = True
                                else:
                                    visited_inodes.add(inode_key)

                            # Resolve owner/group and human-readable octal permissions
                            owner, group = _resolve_owner_and_group(st.st_uid, st.st_gid)
                            perm_octal = oct(stat.S_IMODE(st.st_mode))

                            file_meta = FileMetadata(
                                path=entry.path,
                                size=st.st_size,
                                mtime=st.st_mtime,
                                atime=st.st_atime,
                                owner=owner,
                                group=group,
                                permissions=perm_octal,
                                inode=st.st_ino,
                                device=st.st_dev,
                                is_hardlink_duplicate=is_duplicate,
                            )

                            files_list.append(file_meta)
                            total_files_scanned += 1

                            # If this file points to a duplicate inode (hard link), do not double-count its size
                            if not is_duplicate:
                                total_bytes_scanned += st.st_size

                            if progress_callback is not None and (total_files_scanned % 10 == 0 or total_files_scanned <= 10):
                                progress_callback(total_files_scanned, total_bytes_scanned, current_dir)

                    except (PermissionError, FileNotFoundError, OSError) as entry_err:
                        # Gracefully handle file-level permission or access errors
                        logger.warning(f"Unreadable file entry '{entry.path}': {entry_err}")
                        unreadable_paths.append(entry.path)

        except (PermissionError, FileNotFoundError, OSError) as dir_err:
            # Gracefully handle directory-level permission or access errors
            logger.warning(f"Unreadable directory '{current_dir}': {dir_err}")
            unreadable_paths.append(current_dir)

    return ScanResult(
        target_path=abs_target,
        files=files_list,
        unreadable_paths=unreadable_paths,
        total_files_scanned=total_files_scanned,
        total_bytes_scanned=total_bytes_scanned,
        disk_total=disk_total,
        disk_used=disk_used,
        disk_free=disk_free,
    )
