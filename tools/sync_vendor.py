#!/usr/bin/env python3
"""Synchronize and verify the vendored QA Sentinels tree.

The engine under ``sentinels/`` is a plain vendored copy, not a submodule, so
``git archive`` and the PPA source package stay self-contained. This tool is the
single implementation for writing and checking that copy.

Only annotated ``vMAJOR.MINOR.PATCH`` tags should be vendored. A full commit is
accepted with ``--allow-commit`` for bootstrapping a tree whose release was not
tagged.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = "https://github.com/scripting-drafts/QA-Sentinels"
VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.MULTILINE)
CHANGELOG_RE = re.compile(r"^\S+\s+\(([^)]+)\)")
TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
MANIFEST_RE = re.compile(r"^([0-9a-f]{64})  (sentinels/.+)$")
QA_DASHBOARD_RE = re.compile(r'("qa-dashboard"\s*:\s*")([^"]+)(")')
LEGAL_MANIFEST = "legal/manifest.json"


class SyncError(RuntimeError):
    """A source or destination state that cannot be synchronized safely."""


@dataclass(frozen=True)
class Paths:
    root: Path
    vendor: Path
    marker: Path
    manifest: Path
    legal: Path
    contracts: Path
    rules: Path

    @classmethod
    def under(cls, root: Path) -> "Paths":
        root = root.resolve()
        return cls(
            root=root,
            vendor=root / "sentinels",
            marker=root / "sentinels-vendor.json",
            manifest=root / "sentinels-vendor.manifest",
            legal=root / "legal" / "manifest.json",
            contracts=root / "contracts" / "versions.json",
            rules=root / "docs" / "RULES.md",
        )


@dataclass(frozen=True)
class Ref:
    name: str
    commit: str
    verified: bool


@dataclass(frozen=True)
class FileEntry:
    mode: str
    data: bytes


def git(
    source: Path,
    *args: str,
    input_data: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    proc = subprocess.run(
        ["git", "-C", str(source), *args],
        input=input_data,
        capture_output=True,
    )
    if check and proc.returncode != 0:
        message = proc.stderr.decode("utf-8", "replace").strip()
        raise SyncError(f"git {' '.join(args)} failed: {message}")
    return proc


def git_text(source: Path, *args: str) -> str:
    return git(source, *args).stdout.decode("utf-8").strip()


def find_source(paths: Paths, explicit: str | None) -> Path | None:
    required = explicit or os.environ.get("QA_SENTINELS_SOURCE")
    candidates: list[Path] = []
    if required:
        candidates.append(Path(required))
    candidates.append(paths.root.parent / "QA-Sentinels")
    for candidate in candidates:
        candidate = candidate.expanduser()
        if (candidate / ".git").exists() and (candidate / "sentinels").is_dir():
            return candidate.resolve()
    if required:
        raise SyncError(f"source checkout not found or invalid: {required}")
    return None


def resolve_ref(
    source: Path,
    value: str,
    *,
    allow_commit: bool,
    require_signature: bool,
) -> Ref:
    tag = git(
        source, "rev-parse", "--verify", f"refs/tags/{value}^{{commit}}",
        check=False,
    )
    if tag.returncode == 0:
        if not TAG_RE.match(value):
            raise SyncError(
                f"release tag must match vMAJOR.MINOR.PATCH: {value}")
        kind = git_text(source, "cat-file", "-t", f"refs/tags/{value}")
        if kind != "tag":
            raise SyncError(f"{value} is a lightweight tag; use an annotated tag")
        commit = tag.stdout.decode("utf-8").strip()
        verified = False
        if require_signature:
            check = git(source, "verify-tag", value, check=False)
            if check.returncode != 0:
                detail = check.stderr.decode("utf-8", "replace").strip()
                raise SyncError(f"tag signature not verified for {value}: {detail}")
            verified = True
        return Ref(name=value, commit=commit, verified=verified)

    if not allow_commit:
        raise SyncError(
            f"{value} is not an annotated release tag; "
            "use --allow-commit only to bootstrap an untagged revision")
    if not COMMIT_RE.match(value):
        raise SyncError(
            "a non-tag revision must be a full 40-character commit hash")
    commit = git_text(
        source, "rev-parse", "--verify", f"{value}^{{commit}}")
    return Ref(name="", commit=commit, verified=False)


def source_entries(source: Path, ref: str) -> dict[str, FileEntry]:
    listing = git(
        source, "ls-tree", "-r", "-z", "--full-tree", ref).stdout
    raw_entries: list[tuple[str, str, str]] = []
    for raw in listing.split(b"\0"):
        if not raw:
            continue
        meta, path = raw.split(b"\t", 1)
        mode, kind, sha = meta.decode("utf-8").split()
        relative = path.decode("utf-8")
        if kind != "blob":
            raise SyncError(f"unsupported source entry {relative} ({kind})")
        if mode not in ("100644", "100755"):
            raise SyncError(
                f"unsupported source mode {mode} for {relative}; "
                "only regular and executable files are vendored")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts:
            raise SyncError(f"unsafe source path: {relative}")
        raw_entries.append((relative, mode, sha))

    if not raw_entries:
        return {}

    batch = git(
        source,
        "cat-file",
        "--batch",
        input_data=b"".join(
            sha.encode("ascii") + b"\n" for _, _, sha in raw_entries),
    ).stdout
    entries: dict[str, FileEntry] = {}
    offset = 0
    for relative, mode, _sha in raw_entries:
        newline = batch.index(b"\n", offset)
        header = batch[offset:newline].split()
        if len(header) != 3 or header[1] != b"blob":
            raise SyncError(f"cannot read source blob for {relative}")
        size = int(header[2])
        start = newline + 1
        data = batch[start:start + size]
        offset = start + size + 1
        entries[relative] = FileEntry(mode=mode, data=data)
    return entries


def source_version(source: Path, ref: str) -> str:
    text = git_text(source, "show", f"{ref}:sentinels/__init__.py")
    match = VERSION_RE.search(text)
    if not match:
        raise SyncError(f"cannot read __version__ at {ref}")
    return match.group(1)


def source_changelog_version(source: Path, ref: str) -> str:
    text = git_text(source, "show", f"{ref}:debian/changelog")
    lines = text.splitlines()
    match = CHANGELOG_RE.match(lines[0]) if lines else None
    if not match:
        raise SyncError(f"cannot read debian/changelog at {ref}")
    return match.group(1)


def vendored_version(paths: Paths) -> str:
    target = paths.vendor / "sentinels" / "__init__.py"
    try:
        text = target.read_text(encoding="utf-8")
    except OSError as error:
        raise SyncError(f"cannot read {target}: {error}") from error
    match = VERSION_RE.search(text)
    if not match:
        raise SyncError(f"cannot read __version__ from {target}")
    return match.group(1)


def destination_files(paths: Paths) -> set[str]:
    """Files that git would include in the vendored subtree.

    Tracked and untracked-but-not-ignored files are both included. Ignored
    runtime directories (var, evidence, journal, tickets, triage) stay out, and
    a tracked file deleted from the worktree is not counted while the deletion
    is waiting to be staged.
    """
    proc = git(
        paths.root,
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
        "--",
        "sentinels",
    )
    files: set[str] = set()
    prefix = "sentinels/"
    for raw in proc.stdout.split(b"\0"):
        if not raw:
            continue
        path = raw.decode("utf-8")
        if not path.startswith(prefix):
            continue
        absolute = paths.root / path
        if absolute.is_file() or absolute.is_symlink():
            files.add(path[len(prefix):])
    return files


def tracked_destination_files(paths: Paths) -> set[str]:
    proc = git(paths.root, "ls-files", "-z", "--", "sentinels")
    prefix = "sentinels/"
    return {
        raw.decode("utf-8")[len(prefix):]
        for raw in proc.stdout.split(b"\0")
        if raw and raw.decode("utf-8").startswith(prefix)
    }


def is_executable(path: Path) -> bool:
    return bool(path.stat().st_mode & 0o111)


def dashboard_rules(text: str) -> str:
    """Apply the Dashboard-specific presentation to the engine rule register."""
    lines = text.splitlines(keepends=True)
    if lines and lines[0].startswith("# "):
        lines[0] = "# QA Sentinels rules\n"
    rendered = "".join(lines)
    if "## Portable platform rules (WIP)" not in rendered:
        rendered = rendered.replace(
            "## Portable platform rules\n",
            "## Portable platform rules (WIP)\n",
            1,
        )
    if rendered and not rendered.endswith("\n"):
        rendered += "\n"
    return rendered


def check_registers(paths: Paths, version: str) -> list[str]:
    errors: list[str] = []
    try:
        legal = json.loads(paths.legal.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"cannot read legal/manifest.json: {error}")
        legal = {}
    reviewed = legal.get("reviewedComponents", {}).get("qa-sentinels")
    component = next(
        (item.get("version") for item in legal.get("components", [])
         if item.get("id") == "qa-sentinels"),
        None,
    )
    if reviewed != version:
        errors.append(
            f"legal reviewed qa-sentinels {reviewed or 'missing'} != {version}")
    if component != version:
        errors.append(
            f"legal component qa-sentinels {component or 'missing'} != {version}")

    try:
        contracts = json.loads(paths.contracts.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"cannot read contracts/versions.json: {error}")
        contracts = {}
    recorded = contracts.get("qa_sentinels")
    if recorded != version:
        errors.append(
            f"contract qa_sentinels {recorded or 'missing'} != {version}")
    return errors


def update_registers(paths: Paths, version: str) -> None:
    legal_text = paths.legal.read_text(encoding="utf-8")
    legal_text, reviewed_count = re.subn(
        r'^(\s*"qa-sentinels"\s*:\s*")([^"]+)(",?\s*)$',
        lambda match: f"{match.group(1)}{version}{match.group(3)}",
        legal_text,
        count=1,
        flags=re.MULTILINE,
    )
    if reviewed_count != 1:
        raise SyncError(
            "cannot locate reviewedComponents.qa-sentinels in legal/manifest.json")

    lines = legal_text.splitlines(keepends=True)
    component_start = next(
        (index for index, line in enumerate(lines)
         if re.match(r'^\s*"id"\s*:\s*"qa-sentinels"\s*,?\s*$', line)),
        None,
    )
    if component_start is None:
        raise SyncError("cannot locate the qa-sentinels legal component")
    replaced = False
    for index in range(component_start + 1, min(component_start + 8, len(lines))):
        line, count = re.subn(
            r'^(\s*"version"\s*:\s*")([^"]+)(",?\s*)$',
            lambda match: f"{match.group(1)}{version}{match.group(3)}",
            lines[index],
            count=1,
        )
        if count:
            lines[index] = line
            replaced = True
            break
    if not replaced:
        raise SyncError("cannot locate the qa-sentinels legal component version")
    paths.legal.write_text("".join(lines), encoding="utf-8")

    contracts_text = paths.contracts.read_text(encoding="utf-8")
    contracts_text, count = re.subn(
        r'("qa_sentinels"\s*:\s*")([^"]+)(")',
        lambda match: f"{match.group(1)}{version}{match.group(3)}",
        contracts_text,
        count=1,
    )
    if count != 1:
        raise SyncError("cannot locate qa_sentinels in contracts/versions.json")
    paths.contracts.write_text(contracts_text, encoding="utf-8")

    errors = check_registers(paths, version)
    if errors:
        raise SyncError("; ".join(errors))


def dashboard_version(paths: Paths) -> str:
    """The Dashboard version mirrored into the vendored legal register."""
    try:
        contracts = json.loads(paths.contracts.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SyncError(f"cannot read contracts/versions.json: {error}") from error
    version = str(contracts.get("qa_dashboard") or "")
    if not version:
        raise SyncError("contracts/versions.json has no qa_dashboard version")
    return version


def mirror_dashboard_legal(data: bytes, version: str) -> bytes:
    """Point the vendored engine's qa-dashboard entries at this release.

    Upstream records the Dashboard version it last saw, which is stale as soon
    as the Dashboard releases. The release guard reads this register, so mirror
    the companion version while leaving every other byte untouched.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SyncError(f"vendored {LEGAL_MANIFEST} is not UTF-8: {error}") from error
    text, count = QA_DASHBOARD_RE.subn(
        lambda match: f"{match.group(1)}{version}{match.group(3)}",
        text,
        count=1,
    )
    if not count:
        return data
    lines = text.splitlines(keepends=True)
    start = next(
        (index for index, line in enumerate(lines)
         if re.match(r'^\s*"id"\s*:\s*"qa-dashboard"\s*,?\s*$', line)),
        None,
    )
    if start is not None:
        for index in range(start + 1, min(start + 8, len(lines))):
            line, replaced = re.subn(
                r'^(\s*"version"\s*:\s*")([^"]+)(",?\s*)$',
                lambda match: f"{match.group(1)}{version}{match.group(3)}",
                lines[index],
                count=1,
            )
            if replaced:
                lines[index] = line
                break
    return "".join(lines).encode("utf-8")


def read_marker(paths: Paths) -> dict[str, object]:
    try:
        data = json.loads(paths.marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SyncError(f"cannot read {paths.marker.name}: {error}") from error
    if not isinstance(data, dict):
        raise SyncError(f"{paths.marker.name} must contain a JSON object")
    return data


def write_marker(paths: Paths, version: str, ref: Ref, source_url: str) -> None:
    payload: dict[str, object] = {
        "source": source_url,
        "version": version,
    }
    if ref.name:
        payload["tag"] = ref.name
        payload["tagVerified"] = ref.verified
    payload["commit"] = ref.commit
    payload["syncedAt"] = datetime.now(timezone.utc).date().isoformat()
    paths.marker.write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_manifest(paths: Paths, files: set[str]) -> None:
    lines: list[str] = []
    for relative in sorted(files):
        data = (paths.vendor / relative).read_bytes()
        lines.append(f"{hashlib.sha256(data).hexdigest()}  sentinels/{relative}")
    paths.manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")


def check_manifest(paths: Paths) -> list[str]:
    errors: list[str] = []
    try:
        text = paths.manifest.read_text(encoding="utf-8")
    except OSError:
        return [f"missing {paths.manifest.name}"]
    recorded: set[str] = set()
    for number, line in enumerate(text.splitlines(), 1):
        if not line:
            continue
        match = MANIFEST_RE.match(line)
        if not match:
            errors.append(f"{paths.manifest.name}:{number}: malformed entry")
            continue
        digest, repository_path = match.groups()
        relative = repository_path[len("sentinels/"):]
        if relative in recorded:
            errors.append(f"{paths.manifest.name}:{number}: duplicate {relative}")
            continue
        recorded.add(relative)
        target = paths.root / repository_path
        if not target.is_file():
            errors.append(f"missing vendored file: {relative}")
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != digest:
            errors.append(f"manifest hash differs: {relative}")

    actual_files = destination_files(paths)
    for relative in sorted(actual_files - recorded):
        errors.append(f"unrecorded vendored file: {relative}")
    for relative in sorted(recorded - actual_files):
        errors.append(f"missing vendored file: {relative}")
    return errors


def check_against_source(
    paths: Paths, source: Path, ref: Ref, marker: dict[str, object]
) -> list[str]:
    errors: list[str] = []
    try:
        mirrored = dashboard_version(paths)
    except SyncError as error:
        return [str(error)]
    entries = source_entries(source, ref.commit)
    version = source_version(source, ref.commit)
    changelog = source_changelog_version(source, ref.commit)
    if version != changelog:
        errors.append(
            f"source __version__ {version} != debian/changelog {changelog}")
    marker_version = str(marker.get("version", ""))
    marker_commit = str(marker.get("commit", ""))
    if version != marker_version:
        errors.append(
            f"source version {version} != marker {marker_version or 'missing'}")
    if ref.commit != marker_commit:
        label = ref.name or ref.commit
        errors.append(
            f"source {label} is {ref.commit} != marker {marker_commit or 'missing'}")
    if ref.name and marker.get("tag") and ref.name != marker.get("tag"):
        errors.append(
            f"source tag {ref.name} != marker {marker['tag']}")

    actual = destination_files(paths)
    expected = set(entries)
    for relative in sorted(expected - actual):
        errors.append(f"missing vendored file: {relative}")
    for relative in sorted(actual - expected):
        errors.append(f"unexpected vendored file: {relative}")

    for relative in sorted(expected & actual):
        entry = entries[relative]
        target = paths.vendor / relative
        try:
            data = target.read_bytes()
        except OSError as error:
            errors.append(f"cannot read {relative}: {error}")
            continue
        expected_data = entry.data
        if relative == LEGAL_MANIFEST:
            expected_data = mirror_dashboard_legal(expected_data, mirrored)
        if data != expected_data:
            errors.append(f"content differs: {relative}")
            continue
        if os.name != "nt":
            wanted = entry.mode == "100755"
            if is_executable(target) != wanted:
                errors.append(f"mode differs: {relative}")

    try:
        expected_rules = dashboard_rules(
            git_text(source, "show", f"{ref.commit}:docs/RULES.md"))
    except SyncError as error:
        errors.append(str(error))
    else:
        try:
            current_rules = paths.rules.read_text(encoding="utf-8")
        except OSError as error:
            errors.append(f"cannot read docs/RULES.md: {error}")
        else:
            if current_rules != expected_rules:
                errors.append("docs/RULES.md is out of date")
    return errors


def write_sync(
    paths: Paths,
    source: Path,
    ref_value: str,
    *,
    allow_commit: bool,
    require_signature: bool,
    generate: bool,
) -> int:
    ref = resolve_ref(
        source,
        ref_value,
        allow_commit=allow_commit,
        require_signature=require_signature,
    )
    entries = source_entries(source, ref.commit)
    version = source_version(source, ref.commit)
    changelog = source_changelog_version(source, ref.commit)
    if version != changelog:
        raise SyncError(
            f"source __version__ {version} != debian/changelog {changelog}")
    if ref.name and ref.name != f"v{version}":
        raise SyncError(
            f"tag {ref.name} does not match source version {version}")

    previous = read_marker(paths)
    source_url = str(previous.get("source") or DEFAULT_SOURCE)

    mirrored = dashboard_version(paths)
    for relative, entry in entries.items():
        target = paths.vendor / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        data = entry.data
        if relative == LEGAL_MANIFEST:
            data = mirror_dashboard_legal(data, mirrored)
        target.write_bytes(data)
        if os.name != "nt":
            os.chmod(target, 0o755 if entry.mode == "100755" else 0o644)

    removed = 0
    for stale in sorted(tracked_destination_files(paths) - set(entries)):
        target = paths.vendor / stale
        try:
            target.unlink()
            removed += 1
        except FileNotFoundError:
            continue
        parent = target.parent
        while parent != paths.vendor:
            try:
                parent.rmdir()
            except OSError:
                break
            parent = parent.parent

    unexpected = destination_files(paths) - set(entries)
    if unexpected:
        raise SyncError(
            "unexpected vendored files: " + ", ".join(sorted(unexpected)))

    rules = dashboard_rules(
        git_text(source, "show", f"{ref.commit}:docs/RULES.md"))
    if not paths.rules.is_file() or paths.rules.read_text(encoding="utf-8") != rules:
        paths.rules.write_text(rules, encoding="utf-8")

    update_registers(paths, version)
    write_marker(paths, version, ref, source_url)
    write_manifest(paths, set(entries))
    errors = check_manifest(paths)
    if errors:
        raise SyncError("; ".join(errors))

    if generate:
        for script, args in (
            ("tools/export_contracts.py", ()),
            ("tools/build_rules_html.py", ()),
        ):
            proc = subprocess.run(
                [sys.executable, str(paths.root / script), *args],
                cwd=paths.root,
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                detail = proc.stderr.strip() or proc.stdout.strip()
                raise SyncError(f"{script} failed: {detail}")

    label = ref.name or ref.commit
    print(
        f"vendor-sync: QA Sentinels {version} at {label} copied "
        f"({len(entries)} files, {removed} removed)")
    if generate:
        print("vendor-sync: contracts and rules page regenerated")
    return 0


def check_sync(
    paths: Paths,
    source: Path | None,
    ref_value: str | None,
    *,
    require_signature: bool,
) -> int:
    errors: list[str] = []
    try:
        marker = read_marker(paths)
    except SyncError as error:
        print(f"vendor-check: {error}", file=sys.stderr)
        return 1

    version = str(marker.get("version", ""))
    commit = str(marker.get("commit", ""))
    if not version:
        errors.append("marker has no version")
    if not commit:
        errors.append("marker has no commit")

    if not source and ref_value:
        print(
            "vendor-check: --ref requires a source checkout", file=sys.stderr)
        return 1

    if source is not None:
        requested = ref_value or commit
        try:
            ref = resolve_ref(
                source,
                requested,
                allow_commit=True,
                require_signature=require_signature,
            )
        except SyncError as error:
            errors.append(str(error))
        else:
            errors.extend(check_against_source(paths, source, ref, marker))
    else:
        print(
            "vendor-check: source checkout not found; "
            "verifying manifest and registers only")

    try:
        actual_version = vendored_version(paths)
    except SyncError as error:
        errors.append(str(error))
    else:
        if actual_version != version:
            errors.append(
                f"vendored version {actual_version} != marker "
                f"{version or 'missing'}")
    errors.extend(check_registers(paths, version))
    errors.extend(check_manifest(paths))

    if errors:
        for error in errors:
            print(f"vendor-check: {error}", file=sys.stderr)
        return 1
    label = f" at {commit}"
    if marker.get("tag"):
        label += f" ({marker['tag']})"
    print(f"vendor-check: QA Sentinels {version}{label} is aligned")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--check", action="store_true",
        help="verify alignment without writing (default)")
    action.add_argument(
        "--write", action="store_true",
        help="copy the source revision into the vendored tree")
    parser.add_argument(
        "--source", help="QA Sentinels checkout (default: QA_SENTINELS_SOURCE "
        "or the sibling ../QA-Sentinels)")
    parser.add_argument(
        "--ref", help="annotated release tag, or full commit with --allow-commit")
    parser.add_argument(
        "--allow-commit", action="store_true",
        help="allow a full commit hash instead of a release tag")
    parser.add_argument(
        "--require-signature", action="store_true",
        help="require a verified signature on release tags")
    parser.add_argument(
        "--generate", action="store_true",
        help="regenerate contracts and the rules page after --write")
    parser.add_argument(
        "--root", default=str(ROOT), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.generate and not args.write:
        parser.error("--generate requires --write")

    paths = Paths.under(Path(args.root))
    mode = "write" if args.write else "check"
    prefix = "vendor-sync" if mode == "write" else "vendor-check"
    try:
        source = find_source(paths, args.source)
        if mode == "write":
            if source is None:
                raise SyncError("a source checkout is required for --write")
            if not args.ref:
                raise SyncError("--write requires --ref (prefer a release tag)")
            return write_sync(
                paths,
                source,
                args.ref,
                allow_commit=args.allow_commit,
                require_signature=args.require_signature,
                generate=args.generate,
            )
        return check_sync(
            paths,
            source,
            args.ref,
            require_signature=args.require_signature,
        )
    except SyncError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
