#!/usr/bin/env python3
"""Block pushes that reuse a release tag for a newer commit.

The guard is deliberately narrow: a missing tag is allowed because the release
build creates it. An existing tag must point at the commit being pushed.
"""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
from pathlib import Path

CHANGELOG_RE = re.compile(r"^\S+\s+\((?P<version>[^)]+)\)")


def run_git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def repository_root(path: Path) -> Path:
    proc = run_git(path, "rev-parse", "--show-toplevel")
    if proc.returncode != 0:
        raise SystemExit(f"not a Git repository: {path}")
    return Path(proc.stdout.strip())


def package_root(root: Path) -> Path:
    if (root / "debian" / "changelog").is_file():
        return root
    candidates = [
        path.parent.parent for path in root.glob("*/debian/changelog") if path.is_file()
    ]
    if len(candidates) == 1:
        return candidates[0]
    raise SystemExit(f"debian/changelog not found under {root}")


def changelog_base(root: Path) -> str:
    proc = subprocess.run(
        ["dpkg-parsechangelog", "-S", "Version"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    version = proc.stdout.strip() if proc.returncode == 0 else ""
    if not version:
        lines = (root / "debian" / "changelog").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
        match = CHANGELOG_RE.match(lines[0]) if lines else None
        if not match:
            raise SystemExit(f"cannot parse debian/changelog under {root}")
        version = match.group("version")
    base = version.split("~", 1)[0]
    if "-0ubuntu" in base:
        base = base.rsplit("-0ubuntu", 1)[0]
    return base


def resolved_commit(root: Path, value: str) -> str:
    proc = run_git(root, "rev-parse", "--verify", f"{value}^{{commit}}")
    if proc.returncode != 0:
        raise SystemExit(f"unknown commit: {value}")
    return proc.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository or package directory")
    parser.add_argument("--commit", help="commit being pushed (default: HEAD)")
    parser.add_argument("--verbose", action="store_true", help="report the checked tag")
    args = parser.parse_args(argv)

    root = repository_root(Path(args.root).expanduser().resolve())
    base = changelog_base(package_root(root))
    tag = f"v{base}"
    if run_git(root, "check-ref-format", f"refs/tags/{tag}").returncode != 0:
        print(f"release-tag guard: invalid tag name: {tag}", file=sys.stderr)
        return 2

    tag_proc = run_git(root, "rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}")
    if tag_proc.returncode != 0:
        if args.verbose:
            print(f"release-tag guard: {tag} is absent; the release build will create it")
        return 0

    tag_commit = tag_proc.stdout.strip()
    target = resolved_commit(root, args.commit or "HEAD")
    if tag_commit == target:
        if args.verbose:
            print(f"release-tag guard: {tag} points at {target[:12]}")
        return 0

    print(
        f"release-tag guard: {tag} points at {tag_commit[:12]}, not {target[:12]}",
        file=sys.stderr,
    )
    root_arg = shlex.quote(str(root))
    print(
        f"Repair with: release-board repair --root {root_arg} --bump --move-tag --commit --confirm",
        file=sys.stderr,
    )
    print(
        "It bumps the version when the release was built or published, and only "
        "replaces a tag that was never consumed.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
