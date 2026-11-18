"""Own-product license and legal compliance register for QA Sentinels."""
from __future__ import annotations

import json
import platform
import re
import sqlite3
from datetime import date, datetime, timezone
from pathlib import Path

from . import config

ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
LICENSE_RE = re.compile(
    r"^[A-Za-z0-9.+-]+(?: (?:AND|OR|WITH) [A-Za-z0-9.+-]+)*$")
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
PATH_RE = re.compile(r"^[A-Za-z0-9._@+/-]+$")
SCOPES = {
    "project", "shipped", "dependency", "build", "runtime", "asset", "system",
    "companion",
}
KINDS = {"text", "html", "external"}
CATEGORIES = {
    "licensing", "distribution", "privacy", "export", "trademark",
    "contributions", "accessibility",
}
STATUSES = {"reviewed", "pending", "not-applicable"}
REVIEW_MAX_AGE_DAYS = 366


class ManifestError(RuntimeError):
    """The legal manifest is missing or invalid."""


def _is_str(value, maximum=500) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum


def _valid_date(value) -> bool:
    if not isinstance(value, str) or not DATE_RE.fullmatch(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return False
    return True


def _valid_path(value) -> bool:
    if not _is_str(value, 300):
        return False
    if value.startswith("/") or "\0" in value or "\\" in value:
        return False
    if not PATH_RE.fullmatch(value):
        return False
    return ".." not in value.split("/")


def manifest_path(root=None) -> Path:
    base = Path(root) if root is not None else config.ROOT
    return base / "legal" / "manifest.json"


def load_manifest(root=None) -> dict:
    target = manifest_path(root)
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read {target}: {exc}") from exc
    errors = validate_manifest(data)
    if errors:
        raise ManifestError("; ".join(errors))
    return data


def validate_manifest(manifest) -> list[str]:
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ["manifest: must be an object"]
    if manifest.get("schemaVersion") != 1:
        errors.append("schemaVersion: must be 1")
    for key in ("product", "spdx", "copyright", "source", "lastReviewed",
                "reviewedVersion"):
        if not _is_str(manifest.get(key), 240):
            errors.append(f"{key}: must be a non-empty string")
    spdx = manifest.get("spdx")
    if isinstance(spdx, str) and not LICENSE_RE.fullmatch(spdx):
        errors.append("spdx: must be an SPDX-style license expression")
    source = manifest.get("source")
    if isinstance(source, str) and not re.fullmatch(r"https://\S+", source):
        errors.append("source: must be an https URL")
    if isinstance(manifest.get("lastReviewed"), str) and not _valid_date(
            manifest["lastReviewed"]):
        errors.append("lastReviewed: must be a valid date")

    components = manifest.get("components")
    if not isinstance(components, list) or not components:
        errors.append("components: must be a non-empty array")
    else:
        seen = set()
        for index, component in enumerate(components):
            where = f"components[{index}]"
            if not isinstance(component, dict):
                errors.append(f"{where}: must be an object")
                continue
            cid = component.get("id")
            if not isinstance(cid, str) or not ID_RE.fullmatch(cid):
                errors.append(f"{where}.id: invalid id")
            elif cid in seen:
                errors.append(f"{where}.id: duplicate id")
            else:
                seen.add(cid)
            if not _is_str(component.get("name"), 120):
                errors.append(f"{where}.name: must be a non-empty string")
            license_value = component.get("license")
            if not isinstance(license_value, str) or not LICENSE_RE.fullmatch(
                    license_value):
                errors.append(f"{where}.license: invalid license expression")
            if component.get("scope") not in SCOPES:
                errors.append(f"{where}.scope: invalid scope")
            if component.get("notice") is not None and not _valid_path(
                    component["notice"]):
                errors.append(f"{where}.notice: invalid relative path")

    documents = manifest.get("documents")
    if not isinstance(documents, list) or not documents:
        errors.append("documents: must be a non-empty array")
    else:
        seen = set()
        for index, document in enumerate(documents):
            where = f"documents[{index}]"
            if not isinstance(document, dict):
                errors.append(f"{where}: must be an object")
                continue
            did = document.get("id")
            if not isinstance(did, str) or not ID_RE.fullmatch(did):
                errors.append(f"{where}.id: invalid id")
            elif did in seen:
                errors.append(f"{where}.id: duplicate id")
            else:
                seen.add(did)
            if not _is_str(document.get("label"), 120):
                errors.append(f"{where}.label: must be a non-empty string")
            if not _valid_path(document.get("path")):
                errors.append(f"{where}.path: invalid relative path")
            if document.get("kind") not in KINDS:
                errors.append(f"{where}.kind: invalid kind")

    reviews = manifest.get("reviews")
    if not isinstance(reviews, list):
        errors.append("reviews: must be an array")
    else:
        seen = set()
        for index, review in enumerate(reviews):
            where = f"reviews[{index}]"
            if not isinstance(review, dict):
                errors.append(f"{where}: must be an object")
                continue
            rid = review.get("id")
            if not isinstance(rid, str) or not ID_RE.fullmatch(rid):
                errors.append(f"{where}.id: invalid id")
            elif rid in seen:
                errors.append(f"{where}.id: duplicate id")
            else:
                seen.add(rid)
            if review.get("category") not in CATEGORIES:
                errors.append(f"{where}.category: invalid category")
            if review.get("status") not in STATUSES:
                errors.append(f"{where}.status: invalid status")
            if not _valid_date(review.get("date")):
                errors.append(f"{where}.date: invalid date")
            note = review.get("note")
            if not isinstance(note, str) or len(note) > 500:
                errors.append(f"{where}.note: invalid note")
    return errors


def runtime_facts() -> dict:
    from . import __version__

    return {
        "version": __version__,
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "product": config.PROJECT_NAME,
    }


def _document(root: Path, manifest: dict, doc_id: str) -> dict:
    document = next(
        (item for item in manifest.get("documents", []) if item.get("id") == doc_id),
        None,
    )
    if not document:
        return {"id": doc_id, "available": False, "size": 0, "path": ""}
    path = root / document["path"]
    try:
        resolved = path.resolve()
        if resolved != root.resolve() and root.resolve() not in resolved.parents:
            raise OSError("outside application root")
        if not resolved.is_file():
            raise OSError("not a file")
        size = resolved.stat().st_size
        return {
            "id": doc_id,
            "available": True,
            "size": size,
            "path": document["path"],
            "label": document.get("label", doc_id),
        }
    except OSError:
        return {
            "id": doc_id,
            "available": False,
            "size": 0,
            "path": document.get("path", ""),
            "label": document.get("label", doc_id),
        }


def _check(check_id: str, category: str, label: str, status: str,
           detail: str, evidence: str = "") -> dict:
    return {
        "id": check_id,
        "category": category,
        "label": label,
        "status": status,
        "detail": detail,
        "evidence": evidence,
    }


def _version_matches(expected: str, actual: str) -> bool:
    if not expected or not actual:
        return False
    if expected.endswith("+"):
        return actual == expected[:-1] or actual.startswith(expected[:-1] + ".")
    return expected == actual


def evaluate(manifest: dict, facts: dict, root: Path,
             today: date | None = None) -> list[dict]:
    root = Path(root)
    checks: list[dict] = []
    today = today or date.today()

    document = _document(root, manifest, "license")
    text = ""
    if document["available"]:
        try:
            text = (root / document["path"]).read_text(encoding="utf-8")
        except OSError:
            text = ""
    text_ok = ("Permission is hereby granted, free of charge" in text
               and 'THE SOFTWARE IS PROVIDED "AS IS"' in text)
    checks.append(_check(
        "license-text", "licensing", "Full MIT license text",
        "pass" if document["available"] and text_ok else "action",
        "LICENSE contains the full MIT notice."
        if document["available"] and text_ok
        else "LICENSE is missing or incomplete.",
        "LICENSE",
    ))

    for doc_id, category, label, evidence in (
        ("third-party", "distribution", "Third-party notices",
         "THIRD-PARTY-NOTICES.md"),
        ("privacy", "privacy", "Privacy and data handling", "docs/PRIVACY.md"),
        ("contributions", "contributions", "Contribution and DCO policy",
         "CONTRIBUTING.md"),
        ("security", "distribution", "Security policy", "SECURITY.md"),
        ("debian-copyright", "distribution", "Debian copyright",
         "debian/copyright"),
        ("legal-policy", "licensing", "Legal and release policy",
         "docs/LEGAL.md"),
    ):
        status = _document(root, manifest, doc_id)
        checks.append(_check(
            f"document-{doc_id}", category, label,
            "pass" if status["available"] else "action",
            f"{evidence} is present." if status["available"]
            else f"{evidence} is missing or outside the workspace.",
            evidence,
        ))

    version_ok = facts.get("version") == manifest.get("reviewedVersion")
    checks.append(_check(
        "review-version", "licensing", "Review covers this version",
        "pass" if version_ok else "warn",
        f"Reviewed for {manifest.get('reviewedVersion')}; running {facts.get('version')}.",
        "legal/manifest.json",
    ))

    reviewed = manifest.get("lastReviewed", "")
    try:
        age = (today - datetime.strptime(reviewed, "%Y-%m-%d").date()).days
    except (TypeError, ValueError):
        age = 10**6
    fresh = 0 <= age <= REVIEW_MAX_AGE_DAYS
    checks.append(_check(
        "review-age", "licensing", "Review is current",
        "pass" if fresh else "warn",
        f"Last reviewed {reviewed}." if fresh
        else f"Last review is {age} days old or missing; review annually.",
        "legal/manifest.json",
    ))

    version_map = {
        "qa-sentinels": facts.get("version", ""),
        "python": facts.get("python", ""),
        "sqlite": facts.get("sqlite", ""),
    }
    for component in manifest.get("components", []):
        source = component.get("versionFrom")
        if not source:
            continue
        actual = version_map.get(source, "")
        expected = component.get("version", "")
        matched = _version_matches(expected, actual)
        checks.append(_check(
            f"component-{component['id']}", "distribution",
            f"{component['name']} version",
            "pass" if matched else "warn",
            f"{component['name']} is {actual or 'unknown'}; the manifest reviews "
            f"{expected or 'unknown'}.",
            "legal/manifest.json",
        ))

    missing = [
        item["label"] for item in manifest.get("documents", [])
        if item.get("kind") != "external"
        and not _document(root, manifest, item["id"])["available"]
    ]
    checks.append(_check(
        "documents", "distribution", "Legal document set",
        "action" if missing else "pass",
        f"Missing: {', '.join(missing)}." if missing
        else f"{len(manifest.get('documents', []))} documents are present.",
        "legal/manifest.json",
    ))
    return checks


def summarize(checks: list[dict], reviews: list[dict], version_ok: bool) -> dict:
    pending = [review for review in reviews if review.get("status") == "pending"]
    actions = sum(1 for item in checks if item["status"] == "action")
    warnings = sum(1 for item in checks if item["status"] == "warn") + len(pending)
    return {
        "overall": "action" if actions else "review" if warnings else "ok",
        "actions": actions,
        "warnings": warnings,
        "pending_reviews": len(pending),
        "checks": len(checks),
        "reviews": len(reviews),
        "pass": sum(1 for item in checks if item["status"] == "pass"),
        "version_ok": version_ok,
    }


def register(root=None, today: date | None = None) -> dict:
    base = Path(root) if root is not None else config.ROOT
    try:
        manifest = load_manifest(base)
    except ManifestError as exc:
        return {
            "ok": False,
            "error": str(exc),
            "manifest": {},
            "facts": {},
            "checks": [],
            "reviews": [],
            "documents": [],
            "summary": {
                "overall": "action", "actions": 1, "warnings": 0,
                "pending_reviews": 0, "checks": 0, "reviews": 0, "pass": 0,
                "version_ok": False,
            },
        }
    facts = runtime_facts()
    checks = evaluate(manifest, facts, base, today=today)
    reviews = [dict(review) for review in manifest.get("reviews", [])]
    documents = [
        _document(base, manifest, document["id"])
        for document in manifest.get("documents", [])
    ]
    version_ok = facts.get("version") == manifest.get("reviewedVersion")
    return {
        "ok": True,
        "manifest": manifest,
        "facts": facts,
        "checks": checks,
        "reviews": reviews,
        "documents": documents,
        "summary": summarize(checks, reviews, version_ok),
    }


def print_register(data: dict) -> None:
    if not data.get("ok"):
        print(f"legal register: {data.get('error', 'unavailable')}")
        return
    manifest = data["manifest"]
    facts = data["facts"]
    summary = data["summary"]
    print(f"{manifest['product']} {facts['version']} — {manifest['spdx']}")
    print(f"source        : {manifest['source']}")
    print(f"last reviewed : {manifest['lastReviewed']} "
          f"(covers {manifest['reviewedVersion']})")
    print(f"overall       : {summary['overall']} "
          f"({summary['actions']} actions, {summary['warnings']} warnings, "
          f"{summary['pending_reviews']} pending reviews)")
    print()
    print("components")
    for component in manifest.get("components", []):
        version = component.get("version", "")
        print(f"  {component['name']:<34} {version:<10} "
              f"{component['license']:<34} {component['scope']}")
    print()
    print("checks")
    for item in data["checks"]:
        print(f"  [{item['status']:<6}] {item['label']}: {item['detail']}")
    print()
    print("reviews")
    for review in data["reviews"]:
        print(f"  [{review['status']:<14}] {review['category']}: {review['note']}")
    print()
    print("documents")
    for document in data["documents"]:
        state = "ok" if document["available"] else "missing"
        print(f"  [{state:<7}] {document.get('label', document['id'])} "
              f"({document.get('path', '')})")
