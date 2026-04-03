#!/usr/bin/env python3
"""Backfill proof index from existing proof files.

One-time migration script. Run after deploying v1.4.0 to index all proofs
created before the proof index was introduced.

Idempotent: safe to run multiple times (Redis ZADD is idempotent; JSONL
deduplicates on query via set). Existing index entries are not duplicated.

Usage:
    python3 scripts/backfill_proof_index.py
    python3 scripts/backfill_proof_index.py --dry-run
    python3 scripts/backfill_proof_index.py --verbose
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure trust_layer is importable from the project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from trust_layer.config import PROOFS_DIR
from trust_layer.proof_index import get_proof_index


def main():
    parser = argparse.ArgumentParser(description="Backfill proof index from proofs/ directory")
    parser.add_argument("--dry-run", action="store_true", help="Count proofs without writing")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print each indexed proof")
    args = parser.parse_args()

    proof_files = sorted(PROOFS_DIR.glob("prf_*.json"))
    total = len(proof_files)
    print(f"Found {total} proof files in {PROOFS_DIR}")

    if args.dry_run:
        print("DRY RUN — no index entries will be written")
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
            index.record(fp, proof_id, ts_unix)
            indexed += 1
            if args.verbose:
                print(f"  OK   {proof_id} (fp={fp[:8]}... ts={ts_str[:10]})")
        except Exception as e:
            print(f"  ERR  {proof_id}: {e}", file=sys.stderr)
            skipped += 1

    print(f"\nBackfill complete: {indexed} indexed, {skipped} skipped (total {total})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
