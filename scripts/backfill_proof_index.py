#!/usr/bin/env python3
"""Backfill / reconcile the proof index from proof files or the JSONL index.

Two modes
---------
1. **From proof files** (default): scans `data/proofs/prf_*.json`, extracts
   fingerprint + timestamp, and calls `get_proof_index().record()`.
   Use this after the first deploy of the proof index, or after a data
   migration that added new proof files.

2. **From JSONL** (`--from-jsonl`): reads `data/proof_index.jsonl` and
   replays entries directly into Redis. Faster than scanning proof files.
   Use this to rebuild Redis after a Redis restart.

Both modes are idempotent: Redis ZADD on an existing entry is a no-op;
JSONL `record()` appends a duplicate but query() deduplicates via set().

Usage
-----
    # Full backfill from proof files (first deploy)
    python3 scripts/backfill_proof_index.py

    # Replay JSONL → Redis (after Redis restart)
    python3 scripts/backfill_proof_index.py --from-jsonl

    # Incremental: only entries newer than a timestamp (ISO 8601)
    python3 scripts/backfill_proof_index.py --from-jsonl --since 2026-04-01T00:00:00Z

    # Dry run
    python3 scripts/backfill_proof_index.py --dry-run
    python3 scripts/backfill_proof_index.py --from-jsonl --dry-run --verbose
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure trust_layer is importable from the project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from trust_layer.config import PROOFS_DIR, PROOF_INDEX_FILE
from trust_layer.proof_index import get_proof_index


def _parse_since(since_str: str) -> float:
    try:
        dt = datetime.fromisoformat(since_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError) as e:
        print(f"ERROR: invalid --since value '{since_str}': {e}", file=sys.stderr)
        sys.exit(1)


def backfill_from_proof_files(args, since_unix: float | None) -> int:
    """Scan proof files and index each one."""
    proof_files = sorted(PROOFS_DIR.glob("prf_*.json"))
    total = len(proof_files)
    print(f"Found {total} proof files in {PROOFS_DIR}")

    if args.dry_run:
        print("DRY RUN — no index entries will be written")
        # Still count qualifying files
        if since_unix is not None:
            qualifying = 0
            for path in proof_files:
                try:
                    proof = json.loads(path.read_text())
                    ts_str = proof.get("timestamp", "")
                    ts_unix = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
                    if ts_unix >= since_unix:
                        qualifying += 1
                except Exception:
                    pass
            print(f"Would index {qualifying}/{total} files (since filter applied)")
        return 0

    index = get_proof_index()
    indexed = 0
    skipped = 0

    for path in proof_files:
        try:
            proof = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            print(f"  SKIP {path.name}: read error — {e}", file=sys.stderr)
            skipped += 1
            continue

        proof_id = proof.get("proof_id", path.stem)
        fp = proof.get("parties", {}).get("buyer_fingerprint", "")
        ts_str = proof.get("timestamp", "")

        if not fp or not ts_str:
            if args.verbose:
                print(f"  SKIP {proof_id}: missing fingerprint or timestamp")
            skipped += 1
            continue

        try:
            ts_unix = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
            if since_unix is not None and ts_unix < since_unix:
                if args.verbose:
                    print(f"  SKIP {proof_id}: before --since threshold")
                skipped += 1
                continue
            index.record(fp, proof_id, ts_unix)
            indexed += 1
            if args.verbose:
                print(f"  OK   {proof_id} (fp={fp[:8]}... ts={ts_str[:10]})")
        except Exception as e:
            print(f"  ERR  {proof_id}: {e}", file=sys.stderr)
            skipped += 1

    print(f"\nBackfill complete: {indexed} indexed, {skipped} skipped (total {total})")
    return 0


def backfill_from_jsonl(args, since_unix: float | None) -> int:
    """Replay JSONL entries directly into the index (Redis rebuild)."""
    if not PROOF_INDEX_FILE.exists():
        print(f"ERROR: JSONL index not found at {PROOF_INDEX_FILE}", file=sys.stderr)
        return 1

    total_lines = 0
    qualifying = 0
    errors = 0

    # First pass: count
    with PROOF_INDEX_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                total_lines += 1

    print(f"Found {total_lines} entries in {PROOF_INDEX_FILE}")
    if since_unix is not None:
        since_str = datetime.fromtimestamp(since_unix, tz=timezone.utc).isoformat()
        print(f"Filter: since {since_str}")

    if args.dry_run:
        print("DRY RUN — no index entries will be written")
        with PROOF_INDEX_FILE.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    ts = entry.get("ts", 0.0)
                    if since_unix is None or ts >= since_unix:
                        qualifying += 1
                except Exception:
                    pass
        print(f"Would replay {qualifying}/{total_lines} entries")
        return 0

    index = get_proof_index()
    indexed = 0
    skipped = 0

    with PROOF_INDEX_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                fp = entry.get("fp", "")
                pid = entry.get("pid", "")
                ts = entry.get("ts", 0.0)
                if not fp or not pid:
                    skipped += 1
                    continue
                if since_unix is not None and ts < since_unix:
                    skipped += 1
                    continue
                index.record(fp, pid, ts)
                indexed += 1
                if args.verbose:
                    print(f"  OK   {pid} (fp={fp[:8]}... ts={ts})")
            except Exception as e:
                print(f"  ERR  line {line[:60]}: {e}", file=sys.stderr)
                errors += 1
                skipped += 1

    print(f"\nReconciliation complete: {indexed} replayed, {skipped} skipped, {errors} errors")
    return 0 if errors == 0 else 1


def main():
    parser = argparse.ArgumentParser(
        description="Backfill/reconcile the proof index",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full backfill from proof files (first deploy)
  python3 scripts/backfill_proof_index.py

  # Rebuild Redis from JSONL after a Redis restart
  python3 scripts/backfill_proof_index.py --from-jsonl

  # Only replay recent entries (last 24h) into Redis
  python3 scripts/backfill_proof_index.py --from-jsonl --since 2026-04-02T00:00:00Z

  # Dry run to see what would be indexed
  python3 scripts/backfill_proof_index.py --from-jsonl --dry-run
""",
    )
    parser.add_argument(
        "--from-jsonl",
        action="store_true",
        help="Replay proof_index.jsonl → index (faster Redis rebuild)",
    )
    parser.add_argument(
        "--since",
        metavar="ISO8601",
        help="Only process entries newer than this timestamp (e.g. 2026-04-01T00:00:00Z)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Count entries without writing")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print each entry")
    args = parser.parse_args()

    since_unix = _parse_since(args.since) if args.since else None

    if args.from_jsonl:
        return backfill_from_jsonl(args, since_unix)
    else:
        return backfill_from_proof_files(args, since_unix)


if __name__ == "__main__":
    sys.exit(main())
