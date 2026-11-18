#!/usr/bin/env bash
# Publish one package to its Launchpad PPA for every supported Ubuntu series.
#
# The package identity comes from debian/changelog, not the checkout directory.
# Each series gets a unique Debian version (BASE-0ubuntu1~SERIES1) so uploads
# cannot collide and upgrades sort above the previously published base version.
#
#   scripts/release.sh --check
#   scripts/release.sh
#   scripts/release.sh --no-wait
#   scripts/release.sh --package qa-dashboard
#   SERIES="jammy noble" scripts/release.sh --check
set -euo pipefail

PKG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(git -C "$PKG_ROOT" rev-parse --show-toplevel)"
PKG_PREFIX="$(git -C "$PKG_ROOT" rev-parse --show-prefix)"
cd "$PKG_ROOT"

PPA_BASE="https://ppa.launchpadcontent.net/toomanypatterns"
SIGN_KEY="${SIGN_KEY:-F104A3F1CE9A23540AEB8F24F31978E49E85DDCA}"
WAIT_MAX="${WAIT_MAX:-10800}"
WAIT_STEP="${WAIT_STEP:-60}"
DEFAULT_SERIES=(jammy noble resolute stonking)
if [[ -n "${SERIES:-}" ]]; then
  read -r -a DEFAULT_SERIES <<< "$SERIES"
fi
EXPECTED_PACKAGE=""

MODE=sync
while (( $# )); do
  case "$1" in
    --check) MODE=check ;;
    --no-wait) WAIT_MAX=0 ;;
    --package)
      shift
      [[ $# -gt 0 ]] || { echo "--package requires a value" >&2; exit 2; }
      EXPECTED_PACKAGE="$1"
      ;;
    --series)
      shift
      [[ $# -gt 0 ]] || { echo "--series requires a value" >&2; exit 2; }
      read -r -a DEFAULT_SERIES <<< "$1"
      ;;
    -h|--help)
      sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "usage: $0 [--check|--no-wait] [--package NAME] [--series \"SERIES ...\"]" >&2
      exit 2
      ;;
  esac
  shift
done

PKG="$(dpkg-parsechangelog -S Source)"
VERSION="$(dpkg-parsechangelog -S Version)"
BASE_VERSION="${VERSION%%~*}"
BASE_VERSION="${BASE_VERSION%-0ubuntu*}"

if [[ -n "$EXPECTED_PACKAGE" && "$EXPECTED_PACKAGE" != "$PKG" ]]; then
  echo "package mismatch: changelog says $PKG, --package says $EXPECTED_PACKAGE" >&2
  exit 2
fi

case "$PKG" in
  qa-dashboard)
    PPA=qa-dashboard
    VERSION_FILES=(package.json package-lock.json README.md)
    TEST_CMD=(npm test)
    ;;
  qa-sentinels)
    PPA=qa-sentinels
    VERSION_FILES=(legal/manifest.json)
    TEST_CMD=(python3 -m unittest discover -s tests)
    ;;
  *)
    echo "unsupported source package: $PKG" >&2
    exit 2
    ;;
esac

PPA_HOST="$PPA_BASE/$PPA/ubuntu"
DPUT_TARGET="${DPUT_TARGET:-$PPA}"

series_version() {
  local series="$1"
  if [[ "$BASE_VERSION" == *-* ]]; then
    printf '%s+%s\n' "$BASE_VERSION" "$series"
  else
    printf '%s-0ubuntu1~%s1\n' "$BASE_VERSION" "$series"
  fi
}

series_release() {
  curl -fsS --max-time 30 "$PPA_HOST/dists/$1/Release" >/dev/null 2>&1
}

published_version() {
  local series="$1"
  curl -fsS --max-time 30 \
    "$PPA_HOST/dists/$series/main/binary-amd64/Packages.gz" 2>/dev/null \
    | gunzip -c 2>/dev/null \
    | awk -v p="$PKG" '$1=="Package:"{cur=$2} cur==p && $1=="Version:"{print $2; exit}' \
    || true
}

version_files_ok() {
  local missing=0
  for f in "${VERSION_FILES[@]}"; do
    if [[ -f "$f" ]] && ! grep -q -- "$BASE_VERSION" "$f"; then
      echo "outdated:   $f does not mention $BASE_VERSION" >&2
      missing=1
    fi
  done
  return "$missing"
}

dirty="$(git -C "$REPO_ROOT" status --porcelain | wc -l)"
branch="$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)"
ahead_behind="$(git -C "$REPO_ROOT" rev-list --left-right --count "origin/$branch...HEAD" 2>/dev/null || echo '? ?')"

if [[ "$MODE" == check ]]; then
  echo "package:    $PKG"
  echo "repo:       $REPO_ROOT ($branch)"
  echo "base:       $BASE_VERSION"
  echo "ppa:        $PPA"
  [[ $dirty -eq 0 ]] || echo "dirty:      $dirty file(s) not committed"
  [[ "$ahead_behind" == "0	0" ]] || echo "unpushed:   $ahead_behind (behind/ahead)"
  drift=0
  version_files_ok || drift=1
  for series in "${DEFAULT_SERIES[@]}"; do
    expected="$(series_version "$series")"
    if ! series_release "$series"; then
      echo "  $series: series not enabled in $PPA (expected $expected)"
      drift=1
      continue
    fi
    published="$(published_version "$series")"
    published="${published:-not published}"
    echo "  $series: expected=$expected published=$published"
    [[ "$published" == "$expected" ]] || drift=1
  done
  if [[ $dirty -eq 0 && "$ahead_behind" == "0	0" && $drift -eq 0 ]]; then
    echo "status:     in sync"
    exit 0
  fi
  echo "status:     drift"
  exit 1
fi

if [[ $dirty -ne 0 ]]; then
  echo "working tree is dirty; commit or stash before releasing" >&2
  git -C "$REPO_ROOT" status --short >&2
  exit 1
fi
if [[ "$branch" != main ]]; then
  echo "release from main, not $branch" >&2
  exit 1
fi
if [[ "$ahead_behind" != "0	0" ]]; then
  echo "branch is not in sync with origin/$branch: $ahead_behind (behind/ahead)" >&2
  exit 1
fi
version_files_ok || exit 1

for series in "${DEFAULT_SERIES[@]}"; do
  if ! series_release "$series"; then
    echo "series $series is not enabled in $PPA; enable it in Launchpad first" >&2
    exit 2
  fi
done

echo "testing $PKG $BASE_VERSION"
"${TEST_CMD[@]}"

for series in "${DEFAULT_SERIES[@]}"; do
  expected="$(series_version "$series")"
  published="$(published_version "$series")"
  if [[ "$published" == "$expected" ]]; then
    echo "$PKG $expected is already published for $series"
    continue
  fi

  tmp="$(mktemp -d "${TMPDIR:-/tmp}/qa-release-${PKG}-${series}.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT

  if [[ -n "${PKG_PREFIX%/}" ]]; then
    git -C "$REPO_ROOT" archive --format=tar "HEAD:${PKG_PREFIX%/}" \
      | tar -x -C "$tmp"
  else
    git -C "$REPO_ROOT" archive --format=tar HEAD \
      | tar -x -C "$tmp" --exclude='sentinels'
  fi

  # The Dashboard source build needs the Electron distribution; it is ignored
  # by git but present in a normal checkout, as it was for the original PPA.
  if [[ -d "$PKG_ROOT/node_modules/electron" ]]; then
    mkdir -p "$tmp/node_modules"
    cp -a "$PKG_ROOT/node_modules/electron" "$tmp/node_modules/"
  fi

  python3 - "$tmp/debian/changelog" "$expected" "$series" <<'PY'
from pathlib import Path
import re
import sys

path, version, series = sys.argv[1:4]
text = Path(path).read_text(encoding="utf-8")
lines = text.splitlines()
if not lines:
    raise SystemExit(f"empty changelog: {path}")
line = lines[0]
line = re.sub(r"\([^)]*\)", f"({version})", line, count=1)
line = re.sub(r"\)\s+\S+;", f") {series};", line, count=1)
lines[0] = line
Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

  echo "building $PKG $expected for $series"
  (
    cd "$tmp"
    export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
    dpkg-buildpackage -S -sa "-k$SIGN_KEY"
  )

  changes="$(dirname "$tmp")/${PKG}_${expected}_source.changes"
  [[ -f "$changes" ]] || { echo "missing $changes" >&2; exit 1; }

  echo "uploading $changes to $DPUT_TARGET ($series)"
  dput "$DPUT_TARGET" "$changes"

  rm -rf "$tmp"
  trap - EXIT

  if [[ $WAIT_MAX -gt 0 ]]; then
    echo "waiting for $PKG $expected on $series (up to $((WAIT_MAX / 60)) min)"
    waited=0
    while (( waited < WAIT_MAX )); do
      sleep "$WAIT_STEP"
      waited=$((waited + WAIT_STEP))
      now="$(published_version "$series")"
      if [[ "${now:-}" == "$expected" ]]; then
        echo "published: $PKG $expected on $series"
        break
      fi
    done
    if [[ "${now:-}" != "$expected" ]]; then
      echo "not published yet: $PKG $expected on $series" >&2
      exit 1
    fi
  fi
done
