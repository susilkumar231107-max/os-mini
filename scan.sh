#!/usr/bin/env bash
# ==============================================================================
# scan.sh - Fast Read-Only Filesystem Scanner (Bash Helper)
#
# Uses core Linux/Unix utilities (df, du, find, awk) to perform a quick,
# non-destructive inspection of disk usage and large/stale files.
#
# Requirements met:
# - Displays overall disk usage summary via 'df -h'
# - Identifies top 10 largest directories using 'du'
# - Finds files larger than 100M using 'find'
# - Finds files not modified in 180+ days using 'find'
# - Calculates total size of matched large and stale files
# - Strictly READ-ONLY (no mutation/deletion operations)
# ==============================================================================

set -euo pipefail

# Default target directory is current directory, or first CLI argument
TARGET_DIR="${1:-.}"
TARGET_DIR="$(cd "$TARGET_DIR" 2>/dev/null && pwd || echo "$TARGET_DIR")"

if [ ! -d "$TARGET_DIR" ]; then
    echo "Error: Directory '$TARGET_DIR' does not exist." >&2
    exit 1
fi

SEP="================================================================================"
SUBSEP="--------------------------------------------------------------------------------"

echo "$SEP"
echo "           FAST DISK & FILE CLEANUP SCANNER (BASH HELPER)"
echo "$SEP"
echo "Target Directory : $TARGET_DIR"
echo "Scan Timestamp   : $(date '+%Y-%m-%d %H:%M:%S')"
echo "$SUBSEP"

# 1. Overall Filesystem Usage using df
echo "[1] FILESYSTEM USAGE (df -h)"
echo "$SUBSEP"
df -h "$TARGET_DIR"
echo "$SUBSEP"

# 2. Top 10 Largest Directories using du
echo "[2] TOP 10 LARGEST DIRECTORIES (du -h)"
echo "$SUBSEP"
# du -d 1 (or --max-depth=1 on GNU) summarizes direct subdirectories
if du -h -d 1 "$TARGET_DIR" 2>/dev/null | sort -hr | head -n 11 >/dev/null 2>&1; then
    du -h -d 1 "$TARGET_DIR" 2>/dev/null | sort -hr | head -n 11
else
    # Fallback for standard GNU du if -d is unsupported
    du -h --max-depth=1 "$TARGET_DIR" 2>/dev/null | sort -hr | head -n 11 || true
fi
echo "$SUBSEP"

# Helper function to convert human-readable bytes using awk
format_bytes() {
    awk '
    function human(x) {
        if (x<1024) return sprintf("%d B", x)
        x/=1024
        if (x<1024) return sprintf("%.2f KB", x)
        x/=1024
        if (x<1024) return sprintf("%.2f MB", x)
        x/=1024
        if (x<1024) return sprintf("%.2f GB", x)
        x/=1024
        return sprintf("%.2f TB", x)
    }
    { sum += $1 }
    END { print human(sum) }
    '
}

# 3. Files Larger than 100MB using find
echo "[3] FILES LARGER THAN 100 MB"
echo "$SUBSEP"

# List files with sizes
find "$TARGET_DIR" -type f -size +100M -exec ls -lh {} + 2>/dev/null | awk '{print $5, "\t", $9}' | head -n 20 || true

# Compute total matched size in bytes using find -exec stat/wc/awk
LARGE_TOTAL=$(find "$TARGET_DIR" -type f -size +100M -exec wc -c {} + 2>/dev/null | awk '{if ($2 != "total") print $1}' | format_bytes)
echo "--------------------------------------------------------------------------------"
echo "Total size of files > 100 MB: ${LARGE_TOTAL:-0 B}"
echo "$SUBSEP"

# 4. Files Not Modified in 180+ Days using find
echo "[4] STALE FILES (NOT MODIFIED IN 180+ DAYS)"
echo "$SUBSEP"

find "$TARGET_DIR" -type f -mtime +180 -exec ls -lh {} + 2>/dev/null | awk '{print $5, "\t", $6, $7, $8, "\t", $9}' | head -n 20 || true

STALE_TOTAL=$(find "$TARGET_DIR" -type f -mtime +180 -exec wc -c {} + 2>/dev/null | awk '{if ($2 != "total") print $1}' | format_bytes)
echo "--------------------------------------------------------------------------------"
echo "Total size of files not modified in 180+ days: ${STALE_TOTAL:-0 B}"
echo "$SEP"
echo "[*] Scan complete. This tool is read-only and no files were modified or deleted."
