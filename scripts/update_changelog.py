#!/usr/bin/env python3
"""
update_changelog.py — Prepend a new version entry to CHANGELOG.md.

Usage (called by GitHub Actions after tagging):
    python3 scripts/update_changelog.py <new_tag> <prev_tag>

Example:
    python3 scripts/update_changelog.py v1.3.0 v1.2.0

The script:
1. Collects commits between prev_tag and new_tag via `git log`
2. Groups them by conventional-commit type (feat, fix, security, docs, chore)
3. Prepends the formatted entry to CHANGELOG.md (above [Unreleased])
4. Exits 0 — the caller (CI) commits the result
"""

import re
import subprocess
import sys
from datetime import date
from pathlib import Path

CHANGELOG = Path(__file__).parent.parent / "CHANGELOG.md"

# Conventional commit type → section label (ordered for output)
SECTIONS = [
    ("breaking", "Breaking Changes"),
    ("security", "Security"),
    ("feat",     "Added"),
    ("fix",      "Fixed"),
    ("perf",     "Performance"),
    ("docs",     "Documentation"),
    ("refactor", "Changed"),
    ("test",     "Tests"),
    ("chore",    "Internal"),
]

# Prefixes to skip entirely (noise)
SKIP_PREFIXES = ("chore: bump version", "Merge ", "chore(release)")


def git_log(from_ref: str, to_ref: str) -> list[str]:
    result = subprocess.run(
        ["git", "log", f"{from_ref}..{to_ref}", "--pretty=format:%s", "--no-merges"],
        capture_output=True, text=True, check=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def classify(subject: str) -> str:
    """Return section key for a commit subject."""
    lower = subject.lower()
    if "breaking" in lower or "breaking change" in lower:
        return "breaking"
    # conventional commit prefix
    m = re.match(r"^(\w+)[\(!:]", subject)
    if m:
        prefix = m.group(1).lower()
        if prefix in ("security",):
            return "security"
        for key, _ in SECTIONS:
            if prefix == key:
                return key
    if "security" in lower or "ssrf" in lower or "cve" in lower:
        return "security"
    return "chore"


def format_subject(subject: str) -> str:
    """Strip conventional commit prefix for cleaner display."""
    return re.sub(r"^[\w]+(?:\([^)]*\))?!?:\s*", "", subject).strip()


def build_entry(tag: str, commits: list[str]) -> str:
    version = tag.lstrip("v")
    today = date.today().isoformat()
    buckets: dict[str, list[str]] = {key: [] for key, _ in SECTIONS}

    for subject in commits:
        if any(subject.startswith(skip) for skip in SKIP_PREFIXES):
            continue
        key = classify(subject)
        buckets[key].append(format_subject(subject))

    lines = [f"## [{version}] — {today}", ""]
    has_content = False
    for key, label in SECTIONS:
        items = buckets.get(key, [])
        if not items:
            continue
        has_content = True
        lines.append(f"### {label}")
        for item in items:
            lines.append(f"- {item}")
        lines.append("")

    if not has_content:
        lines.append("_(no user-facing changes)_")
        lines.append("")

    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def update_changelog(entry: str) -> None:
    content = CHANGELOG.read_text(encoding="utf-8")
    lines = content.splitlines(keepends=True)
    insert_at = None

    # Insert after the first "---" separator (end of file header block).
    # This places new entries right after the header, before existing versions.
    for i, line in enumerate(lines):
        if line.strip() == "---":
            insert_at = i + 1
            break

    if insert_at is None:
        # No separator found — append after header
        CHANGELOG.write_text(content.rstrip() + "\n\n" + entry, encoding="utf-8")
        return

    entry_block = "\n" + entry
    lines.insert(insert_at, entry_block)
    CHANGELOG.write_text("".join(lines), encoding="utf-8")


def main() -> None:
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <new_tag> <prev_tag>", file=sys.stderr)
        sys.exit(1)

    new_tag, prev_tag = sys.argv[1], sys.argv[2]
    print(f"Building changelog entry: {prev_tag}..{new_tag}")

    commits = git_log(prev_tag, new_tag)
    print(f"  {len(commits)} commits found")

    entry = build_entry(new_tag, commits)
    update_changelog(entry)
    print(f"  CHANGELOG.md updated — entry for {new_tag}")


if __name__ == "__main__":
    main()
