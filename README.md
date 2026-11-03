# Disk Space and Large-File Cleanup Advisor (Pro Edition)

An advanced Operating Systems mini-project providing a **non-destructive, read-only Linux storage analysis and cleanup advisory engine**.

It includes:
- **Python CLI Tool** (`main.py`)
- **Fast Bash Helper** (`scan.sh` with `df`, `du`, `find`)
- **Advanced Web Dashboard** (`app.py`) built with Flask, Chart.js, and D3.js treemap.
- **Automated Verification & Pytest Suite** (`test_advisor_suite.py`)

---

## 1. Safety Policy (Critical Requirement)
- **Zero Deletion Guarantee**: The application contains **no** deletion or alteration logic (`os.remove`, `os.unlink`, and `shutil.rmtree` are never executed).
- **Proposals Only**: All recommendations are classified by risk tier (`SAFE`, `REVIEW`, `PROTECTED`).
- **Commented Shell Script**: Generates `cleanup_proposal.sh` where **every removal command is safely commented out (`# rm`)**, requiring manual review and uncommenting by the user before running.
- **Strict Boundary Protection**: Bound exclusively to `127.0.0.1`. Traversal unconditionally skips virtual and sensitive system files (`/proc`, `/sys`, `/dev`, `/boot`, `/etc`, `/bin`, `/usr`), and restricts user scanning within safe paths.
- **No Symlink Loops**: Uses `follow_symlinks=False` to prevent cyclic recursion and avoid escaping filesystem mount points.
- **Accurate Inode Accounting**: Tracks `(st_dev, st_ino)` tuples to ensure hard links sharing physical disk blocks are never double-counted.

---

## 2. New Features in Version 2.0

1. **Live Scan Progress Streaming (SSE)**:
   - Real-time Server-Sent Events stream showing files scanned, bytes processed, current directory being traversed, and elapsed time with a progress indicator.
   - **Cancel Scan Button**: Safely stops traversal using `threading.Event`.
2. **Interactive Directory Treemap**:
   - D3.js-powered visual hierarchy of directory storage consumption with zoom-in breadcrumbs.
3. **Smart Cleanup Rules Engine (`rules.json`)**:
   - User-editable heuristics for `__pycache__`, stale `node_modules`, `.cache`, `pip`/`npm` caches, browser caches, thumbnails, temporary files, old rotated logs (`*.log.1.gz`), core dumps, and stale installers (`.iso`, `.deb`).
   - "Rules" tab with toggle switches showing live counts and recoverable bytes matched per rule.
4. **Duplicate Finder 2.0**:
   - 3-stage performance pipeline: Size bucketing &rarr; 4 KB prefix hash &rarr; Full chunked SHA-256.
   - Side-by-side file comparison with modification dates, owners, and paths.
   - Automated selector controls per group: **Keep Newest**, **Keep Oldest**, or **Keep Shortest Path**.
5. **Clean-Up Simulator (Dry Run)**:
   - Select candidate files and run an interactive "Simulate Cleanup" dry run.
   - Displays a before/after comparison chart showing simulated freed space and resulting disk percentage without touching any files.
6. **Disk Health Score & Recommendations**:
   - Composite 0–100 score based on disk usage, inode capacity (`df -i`), stale data ratio, duplicate waste, and cache accumulation.
   - Visual gauge with green/amber/red status and 3 actionable plain-English recommendations.
   - High disk usage alert banner if storage exceeds 80%.
7. **Scan History & Trend Tracking (`./history`)**:
   - Automatically records timestamped scan snapshots as JSON.
   - Interactive trend chart and differential comparison showing which directories grew the most between scans.
8. **Safe Read-Only File Inspector Panel**:
   - Clicking any file opens a side drawer displaying: full path, size, inode, hard link count, owner, group, permissions (`rwxr-xr-x` and octal), `atime`/`mtime`/`ctime`, file type, classification reason, and a read-only 2 KB preview for text files.
9. **Advanced Filters & Saved Presets**:
   - Filter proposal tables by risk level, category, and real-time substring search.
   - Save and load filter presets from browser `localStorage`.
   - Global keyboard shortcut `/` to focus the search bar.
10. **Equivalent Linux Commands Panel**:
    - Maps each tool feature directly to core Linux commands (`df -h -i`, `du -xh -d 1`, `find -size +100M`, `find -mtime +180`, `sha256sum | uniq -w 64 -D`) with one-click copy buttons for viva presentations.
11. **Printable Audit Report**:
    - Dedicated `/report` route with print stylesheets to view or save as PDF.

---

## 3. Operating Systems Concepts (Viva Preparation)

### Q1: What is an Inode and why is it important in disk cleanup?
> **A:** An inode (Index Node) stores all POSIX file metadata (size, UID, GID, permissions, timestamps, data block pointers) separate from the directory entry. A file's name is just a pointer to an inode. Hard links share the same `(st_dev, st_ino)`. Our scanner tracks visited inodes so that hard links pointing to the same data blocks are only counted once in space totals.

### Q2: Why use `os.scandir()` instead of `os.walk()` or `os.listdir()`?
> **A:** `os.scandir()` calls the kernel's `getdents64()` / `readdir()` system call, returning `DirEntry` objects with cached file types (`d_type`) and stat attributes directly from the directory stream. This avoids executing an extra `stat()` system call for every file, speeding up traversal by 2x to 10x.

### Q3: What is the risk of following symbolic links during traversal?
> **A:** Cyclic symlinks (e.g., `folder/link -> folder`) create infinite recursion loops. Furthermore, symlinks can point outside the target workspace into sensitive root directories (`/`, `/etc`). By enforcing `follow_symlinks=False`, the scanner stays strictly within designated bounds.

### Q4: How does 3-stage duplicate detection optimize I/O?
> **A:** Hashing every file with SHA-256 across large disks causes severe disk bottlenecks. The 3-stage check:
> 1. Buckets files by exact byte size without disk I/O; singletons are discarded.
> 2. Reads only a 4 KB prefix hash for size collisions.
> 3. Computes full SHA-256 only on candidates whose size and prefix match.

### Q5: What is the difference between `st_mtime`, `st_atime`, and `st_ctime`?
> **A:**
> - `mtime` (Modification Time): When file content was last written/altered.
> - `atime` (Access Time): When file content was last read (often updated lazily with `relatime` on Linux).
> - `ctime` (Status Change Time): When metadata or inode attributes (permissions, ownership) were changed.

---

## 4. How to Run

### Installation
```bash
pip install -r requirements.txt
```

### Start the Web Dashboard
```bash
python3 app.py
```
Open **`http://127.0.0.1:5000`** in your browser.

Click **"⚡ Load Demo Data"** to automatically populate a synthetic test filesystem (`./demo_data`) and explore all features immediately.

### Run Verification Unit Tests (pytest)
```bash
python3 -m pytest test_advisor_suite.py -v
```

### Run Command-Line Tool
```bash
python3 main.py --path /home/user --min-size 50M --older-than 90 --export json
```

### Run Bash Helper
```bash
./scan.sh /home/user
```
