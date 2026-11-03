#!/usr/bin/env python3
"""
test_advisor.py - Comprehensive Test Suite for Cleanup Advisor.

Verifies:
1. Creation of realistic sample directory tree with:
   - Large sparse file (via truncate / seek)
   - Stale/old file (modified > 200 days ago)
   - Duplicate files (identical SHA-256 hash)
   - Temporary file in a cache directory
   - Regular active file
2. Execution of main.py and scan.sh on this tree.
3. Verification of tool detection:
   - Identifies the large file (> 50M)
   - Identifies the stale file (> 180 days)
   - Identifies duplicate groups and calculates wasted bytes
   - Identifies safe vs. review items in the proposal
4. CRITICAL ZERO-DELETION VERIFICATION:
   - Takes a complete snapshot of all files and inodes before running.
   - Verifies 100% of the files remain completely untouched and intact after running.
"""

import os
import sys
import time
import shutil
import tempfile
import subprocess
import json

def create_sample_tree(base_dir: str):
    """
    Builds sample directory tree using standard truncate/sparse techniques and utime.
    """
    now = time.time()
    day_seconds = 86400

    # 1. Subdirectories
    downloads_dir = os.path.join(base_dir, "Downloads")
    cache_dir = os.path.join(base_dir, ".cache", "test_app")
    logs_dir = os.path.join(base_dir, "logs")
    os.makedirs(downloads_dir, exist_ok=True)
    os.makedirs(cache_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    # 2. Large File (120 MB sparse file via truncate)
    large_file = os.path.join(downloads_dir, "ubuntu-disk.iso")
    with open(large_file, "wb") as f:
        f.truncate(120 * 1024 * 1024)  # 120 MB
    # Set to 100 days old
    t_100_days = now - (100 * day_seconds)
    os.utime(large_file, (t_100_days, t_100_days))

    # 3. Stale/Old File (250 days old, 15 MB)
    stale_file = os.path.join(downloads_dir, "old_backup.tar.gz")
    with open(stale_file, "wb") as f:
        f.truncate(15 * 1024 * 1024)  # 15 MB
    t_250_days = now - (250 * day_seconds)
    os.utime(stale_file, (t_250_days, t_250_days))

    # 4. Duplicate Files (Identical content: 4 KB each)
    dup_content = b"CRITICAL_SYSTEM_TEST_DUPLICATE_PAYLOAD_ABC_123456789\n" * 100
    dup1 = os.path.join(downloads_dir, "document_copy1.pdf")
    dup2 = os.path.join(downloads_dir, "document_copy2.pdf")
    with open(dup1, "wb") as f:
        f.write(dup_content)
    with open(dup2, "wb") as f:
        f.write(dup_content)
    t_15_days = now - (15 * day_seconds)
    os.utime(dup1, (t_15_days, t_15_days))
    os.utime(dup2, (t_15_days, t_15_days))

    # 5. Stale Cache File (SAFE category: 20 days old)
    cache_file = os.path.join(cache_dir, "cache_index.tmp")
    with open(cache_file, "w") as f:
        f.write("temporary cache metadata")
    t_20_days = now - (20 * day_seconds)
    os.utime(cache_file, (t_20_days, t_20_days))

    # 6. Rotated Log File (SAFE category: 45 days old)
    log_file = os.path.join(logs_dir, "app.log.1.gz")
    with open(log_file, "w") as f:
        f.write("compressed rotated log lines")
    t_45_days = now - (45 * day_seconds)
    os.utime(log_file, (t_45_days, t_45_days))

    # 7. Active Recent File (PROTECTED: created just now)
    recent_file = os.path.join(base_dir, "active_project.py")
    with open(recent_file, "w") as f:
        f.write("print('currently active project file')")


def get_tree_snapshot(base_dir: str):
    """
    Captures snapshot of all files, sizes, and inodes in base_dir.
    """
    snapshot = {}
    for root, _, files in os.walk(base_dir):
        for fname in files:
            p = os.path.join(root, fname)
            st = os.stat(p)
            snapshot[p] = (st.st_size, st.st_ino, st.st_mtime)
    return snapshot


def main():
    print("=" * 70)
    print("       DISK CLEANUP ADVISOR - END-TO-END VERIFICATION TEST")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as test_root:
        sample_dir = os.path.join(test_root, "sample_workspace")
        os.makedirs(sample_dir)

        print("[1] Building test directory tree...")
        create_sample_tree(sample_dir)

        # Record snapshot of all files before running anything
        snapshot_before = get_tree_snapshot(sample_dir)
        print(f"    Created {len(snapshot_before)} files in sample tree.")
        for p in sorted(snapshot_before.keys()):
            rel = os.path.relpath(p, sample_dir)
            print(f"      - {rel} ({snapshot_before[p][0]} bytes)")

        # Run main.py with JSON export
        json_report_path = os.path.join(test_root, "test_report.json")
        script_output_path = os.path.join(test_root, "test_proposal.sh")

        print("\n[2] Executing main.py on sample tree...")
        project_root = os.path.abspath(os.path.dirname(__file__))
        cmd = [
            sys.executable,
            os.path.join(project_root, "main.py"),
            "--path", sample_dir,
            "--min-size", "50M",
            "--older-than", "180",
            "--top", "10",
            "--export", "json",
            "--export-file", json_report_path,
            "--generate-script", script_output_path,
        ]
        
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            print("STDERR:\n", proc.stderr)
            raise RuntimeError(f"main.py failed with return code {proc.returncode}")
        
        print("    main.py executed successfully.")

        # Verify JSON report findings
        print("\n[3] Verifying analysis findings...")
        with open(json_report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        large_files = [f["path"] for f in data["top_large_files"]]
        stale_files = [f["path"] for f in data["stale_files"]]
        duplicates = data["duplicates"]
        safe_bytes = data["recoverable_space"]["safe_bytes"]

        print(f"    - Large files detected (> 50M): {len(large_files)}")
        assert any("ubuntu-disk.iso" in p for p in large_files), "Expected ubuntu-disk.iso in large files"

        print(f"    - Stale files detected (> 180 days): {len(stale_files)}")
        assert any("old_backup.tar.gz" in p for p in stale_files), "Expected old_backup.tar.gz in stale files"

        print(f"    - Duplicate groups detected: {len(duplicates)}")
        assert len(duplicates) == 1, f"Expected 1 duplicate group, found {len(duplicates)}"
        assert duplicates[0]["wasted_bytes"] > 0, "Duplicate group should show wasted space"

        print(f"    - Safe recoverable space estimated: {safe_bytes} bytes")
        assert safe_bytes > 0, "Expected non-zero safe recoverable space"

        # Verify generated cleanup script contains commented out commands
        print("\n[4] Verifying generated cleanup script safety...")
        assert os.path.exists(script_output_path), "Proposal script cleanup_proposal.sh was not generated"
        with open(script_output_path, "r", encoding="utf-8") as f:
            script_lines = f.readlines()
        
        # Verify no active rm commands exist
        active_rm_lines = [line.strip() for line in script_lines if line.strip().startswith("rm ")]
        commented_rm_lines = [line.strip() for line in script_lines if line.strip().startswith("# rm ")]
        
        print(f"    - Active rm commands found: {len(active_rm_lines)} (MUST BE 0)")
        print(f"    - Commented-out proposals found: {len(commented_rm_lines)}")
        assert len(active_rm_lines) == 0, "CRITICAL ERROR: Found uncommented rm commands in script!"
        assert len(commented_rm_lines) >= 3, "Expected at least 3 commented-out cleanup candidate items"

        # Run Bash helper script scan.sh
        print("\n[5] Executing scan.sh on sample tree...")
        bash_script = os.path.join(project_root, "scan.sh")
        proc_bash = subprocess.run(["bash", bash_script, sample_dir], capture_output=True, text=True)
        assert proc_bash.returncode == 0, f"scan.sh failed with return code {proc_bash.returncode}"
        print("    scan.sh executed successfully.")

        # CRITICAL TEST: Verify zero deletions occurred
        print("\n[6] CRITICAL VERIFICATION: Checking for zero file deletions...")
        snapshot_after = get_tree_snapshot(sample_dir)

        assert snapshot_before == snapshot_after, "CRITICAL FAILURE: Filesystem was mutated by the tool!"
        print(f"    ALL {len(snapshot_after)} files remain 100% UNTOUCHED, intact, and identical.")

    print("\n" + "=" * 70)
    print(" >>> ALL VERIFICATION TESTS PASSED SUCCESSFULLY! <<<")
    print("=" * 70)

if __name__ == "__main__":
    main()
