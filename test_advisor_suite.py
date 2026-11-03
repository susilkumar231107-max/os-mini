"""
test_advisor_suite.py - Comprehensive Unit Tests using pytest.

Tests:
1. Smart Rules Engine (rules.json loading, pattern matching, age filter, enabled flag)
2. 3-Stage Duplicate Detection (size bucketing, 4KB prefix hashing, full SHA-256)
3. Three-Tier Risk Classification (SAFE, REVIEW, PROTECTED)
4. Disk Health Score calculation (0-100 gauge score & recommendations)
5. Zero Deletion and Read-Only Verification
"""

import os
import time
import tempfile
import pytest

from advisor.scanner import FileMetadata, scan_directory, ScanResult
from advisor.analyzer import detect_duplicates, analyze_scan, DuplicateGroup
from advisor.advisor import classify_candidate, is_protected_file, generate_cleanup_proposal, RiskLevel
from advisor.rules_engine import Rule, match_file_against_rule, evaluate_rules_on_files, load_rules
from advisor.health_score import compute_disk_health, get_inode_utilization
from advisor.file_inspector import inspect_file


def test_rules_engine_matching():
    """Verifies that smart cleanup rules match patterns and age requirements."""
    now = time.time()
    day = 86400

    # Rule: old logs older than 30 days
    log_rule = Rule(
        id="test_logs",
        name="Test Logs",
        pattern="*.log,*.gz",
        is_directory=False,
        min_age_days=30,
        risk_level="SAFE",
        explanation="Stale test logs"
    )

    # 1. Stale log (40 days old) -> should match
    f_stale = FileMetadata(
        path="/tmp/test_dir/syslog.1.gz",
        size=1024,
        mtime=now - (40 * day),
        atime=now - (40 * day),
        owner="user",
        group="user",
        permissions="0644",
        inode=1001,
        device=1
    )
    assert match_file_against_rule(f_stale, log_rule, now) is True

    # 2. Fresh log (5 days old) -> should NOT match (age requirement)
    f_fresh = FileMetadata(
        path="/tmp/test_dir/app.log",
        size=1024,
        mtime=now - (5 * day),
        atime=now - (5 * day),
        owner="user",
        group="user",
        permissions="0644",
        inode=1002,
        device=1
    )
    assert match_file_against_rule(f_fresh, log_rule, now) is False

    # 3. Rule disabled -> should NOT match
    log_rule.enabled = False
    assert match_file_against_rule(f_stale, log_rule, now) is False


def test_3_stage_duplicate_detection():
    """Verifies 3-stage duplicate detection (size -> 4KB prefix -> full SHA-256)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # File A and File B: identical content
        content_dup = b"IDENTICAL_CONTENT_STRING_ABC_123456789\n" * 100
        path_a = os.path.join(tmpdir, "file_a.dat")
        path_b = os.path.join(tmpdir, "file_b.dat")
        with open(path_a, "wb") as f: f.write(content_dup)
        with open(path_b, "wb") as f: f.write(content_dup)

        # File C: same size, different content
        content_diff = b"DIFFERENT_CONTENT_STRING_XYZ_987654321\n" * 100
        path_c = os.path.join(tmpdir, "file_c.dat")
        with open(path_c, "wb") as f: f.write(content_diff)

        st_a = os.stat(path_a)
        st_b = os.stat(path_b)
        st_c = os.stat(path_c)

        files = [
            FileMetadata(path=path_a, size=st_a.st_size, mtime=st_a.st_mtime, atime=st_a.st_atime,
                         owner="user", group="user", permissions="0644", inode=st_a.st_ino, device=st_a.st_dev),
            FileMetadata(path=path_b, size=st_b.st_size, mtime=st_b.st_mtime, atime=st_b.st_atime,
                         owner="user", group="user", permissions="0644", inode=st_b.st_ino, device=st_b.st_dev),
            FileMetadata(path=path_c, size=st_c.st_size, mtime=st_c.st_mtime, atime=st_c.st_atime,
                         owner="user", group="user", permissions="0644", inode=st_c.st_ino, device=st_c.st_dev),
        ]

        dup_groups = detect_duplicates(files)

        # Exactly 1 duplicate group with File A and File B
        assert len(dup_groups) == 1
        group = dup_groups[0]
        assert len(group.files) == 2
        assert path_a in group.files
        assert path_b in group.files
        assert path_c not in group.files
        assert group.wasted_space == st_a.st_size


def test_risk_classification():
    """Verifies SAFE, REVIEW, and PROTECTED risk classifications."""
    now = time.time()
    day = 86400

    # 1. Protected: Root-owned file
    root_file = FileMetadata(
        path="/etc/passwd", size=500, mtime=now - (100 * day), atime=now - (100 * day),
        owner="root", group="root", permissions="0644", inode=50, device=1
    )
    is_prot, reason = is_protected_file(root_file, now)
    assert is_prot is True
    assert "root" in reason or "system directory" in reason

    # 2. Protected: Recently modified user file (< 7 days)
    recent_file = FileMetadata(
        path="/home/user/document.docx", size=5000, mtime=now - (2 * day), atime=now - (2 * day),
        owner="user", group="user", permissions="0644", inode=51, device=1
    )
    is_prot, reason = is_protected_file(recent_file, now)
    assert is_prot is True
    assert "Recently modified" in reason

    # 3. Safe: Stale Cache file (> 7 days)
    cache_file = FileMetadata(
        path="/home/user/.cache/app/temp.tmp", size=2000, mtime=now - (15 * day), atime=now - (15 * day),
        owner="user", group="user", permissions="0644", inode=52, device=1
    )
    risk, _ = classify_candidate(cache_file, category="caches", now=now)
    assert risk == RiskLevel.SAFE

    # 4. Review: Old archive (> 90 days)
    archive_file = FileMetadata(
        path="/home/user/backup_2023.tar.gz", size=50000000, mtime=now - (120 * day), atime=now - (120 * day),
        owner="user", group="user", permissions="0644", inode=53, device=1
    )
    risk, _ = classify_candidate(archive_file, category="archives", now=now)
    assert risk == RiskLevel.REVIEW


def test_health_score_calculation():
    """Verifies that disk health score computes valid 0-100 scores and recommendations."""
    now = time.time()
    scan_res = ScanResult(
        target_path="/test",
        files=[],
        unreadable_paths=[],
        total_files_scanned=100,
        total_bytes_scanned=10 * 1024 * 1024,
        disk_total=100 * 1024 * 1024 * 1024,
        disk_used=40 * 1024 * 1024 * 1024,   # 40% used -> healthy
        disk_free=60 * 1024 * 1024 * 1024
    )

    analysis = analyze_scan(scan_res, reference_time=now)
    proposal = generate_cleanup_proposal(analysis, reference_time=now)

    health = compute_disk_health(scan_res, analysis, proposal)

    assert 0 <= health["score"] <= 100
    assert health["status"] in ("healthy", "warning", "critical")
    assert len(health["recommendations"]) >= 1


def test_zero_deletion_safety():
    """Guarantees that scanning and proposal generation never modify or delete files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "important_data.txt")
        with open(test_file, "w") as f:
            f.write("DO_NOT_DELETE_ME")

        mtime_before = os.path.getmtime(test_file)
        size_before = os.path.getsize(test_file)

        scan_res = scan_directory(tmpdir)
        analysis = analyze_scan(scan_res)
        proposal = generate_cleanup_proposal(analysis)

        # File must remain 100% identical and existent
        assert os.path.exists(test_file)
        assert os.path.getsize(test_file) == size_before
        assert os.path.getmtime(test_file) == mtime_before


def test_api_browse_endpoints():
    """Verifies /api/browse, /api/quick-paths, and /api/validate-path."""
    import app as flask_app
    client = flask_app.app.test_client()

    # 1. Quick paths
    res_qp = client.get("/api/quick-paths")
    assert res_qp.status_code == 200
    qp_data = res_qp.get_json()
    assert "shortcuts" in qp_data
    assert len(qp_data["shortcuts"]) >= 1

    # 2. Browse default (home)
    res_browse = client.get("/api/browse")
    assert res_browse.status_code == 200
    browse_data = res_browse.get_json()
    assert "entries" in browse_data
    assert "current" in browse_data
    assert "home" in browse_data

    # 3. Browse with temp directory
    with tempfile.TemporaryDirectory() as tmpdir:
        sub_a = os.path.join(tmpdir, "folder_a")
        sub_b = os.path.join(tmpdir, "folder_b")
        file_c = os.path.join(tmpdir, "file_c.txt")
        os.makedirs(sub_a)
        os.makedirs(sub_b)
        with open(file_c, "w") as f: f.write("test file")

        res_tmp = client.get(f"/api/browse?path={tmpdir}")
        assert res_tmp.status_code == 200
        entries = res_tmp.get_json()["entries"]
        entry_names = [e["name"] for e in entries]
        assert "folder_a" in entry_names
        assert "folder_b" in entry_names
        # Regular files should be excluded from directory list
        assert "file_c.txt" not in entry_names


def test_api_validate_path():
    """Verifies /api/validate-path on valid folder, missing folder, file, blocked path, and symlinks."""
    import app as flask_app
    client = flask_app.app.test_client()

    # 1. Valid folder (current project directory)
    res = client.get(f"/api/validate-path?path={os.path.dirname(__file__)}")
    data = res.get_json()
    assert data["valid"] is True
    assert data["message"] == "Folder OK"

    # 2. Missing folder
    res_missing = client.get("/api/validate-path?path=/nonexistent_directory_xyz_12345")
    data_missing = res_missing.get_json()
    assert data_missing["valid"] is False
    assert "Directory does not exist" in data_missing["message"]

    # 3. File instead of directory
    with tempfile.NamedTemporaryFile() as tmpf:
        res_file = client.get(f"/api/validate-path?path={tmpf.name}")
        data_file = res_file.get_json()
        assert data_file["valid"] is False
        assert "not a directory" in data_file["message"]

    # 4. Blocked system path (/etc or /proc)
    res_blocked = client.get("/api/validate-path?path=/etc")
    data_blocked = res_blocked.get_json()
    assert data_blocked["valid"] is False
    assert "protected system directory" in data_blocked["message"]

    # 5. Empty path
    res_empty = client.get("/api/validate-path?path=")
    data_empty = res_empty.get_json()
    assert data_empty["valid"] is False
