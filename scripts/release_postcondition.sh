#!/usr/bin/env bash
# Does what PyPI serves for a version match what its tag builds? Content, not archive bytes.
#
# usage: scripts/release_postcondition.sh <version>      (for example 0.6.5)
#
# 1. fetch the sdist and the wheel PyPI lists for the version, and refuse any file whose
#    sha256 is not the one PyPI states,
# 2. clone the repo fresh, check out v<version>, and build both the way release.yml does
#    (SOURCE_DATE_EPOCH from the tagged commit, build 1.6.1),
# 3. unpack the two wheels and the two sdists and compare the trees with diff -r.
#
# The archive sha of a wheel is never the judge: it moves with build time and says nothing
# about what is inside. The second check, equality of the sdist sha256, applies only when the
# tag carries scripts/repack_sdist.sh, because only then is that sha a fact about the commit.
# On a tag without the script (0.6.5) it is reported as NOT APPLICABLE and cannot fail.
#
# Exit 0 only when the content is equal. Exit 1 when it differs, with the first 5 differing
# paths on stderr as `DIFF <which archive>: <path>`. Exit 2 when it could not measure
# (nothing to compare, a failed download, a digest that does not match, no tag, a bad version).
#
# Environment, all optional:
#   PACKAGE (sunglasses)  REPO_URL (the GitHub repo)  PYTHON (python3)
#   PYPI_DIST_DIR / BUILT_DIST_DIR  use these directories of one wheel and one sdist instead
#                                   of fetching or building, for tests
#   REPACK_LIVE (yes|no)            only read with BUILT_DIST_DIR, which has no tag to ask
set -euo pipefail
export LC_ALL=C

die() { echo "release_postcondition: REFUSED: $*" >&2; exit 2; }

VERSION="${1:-}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "usage: release_postcondition.sh <version> (digits and dots, like 0.6.5), got '${VERSION}'"
PACKAGE="${PACKAGE:-sunglasses}"
REPO_URL="${REPO_URL:-https://github.com/sunglasses-dev/sunglasses.git}"
PYTHON="${PYTHON:-python3}"
TAG="v${VERSION}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/pypi" "$work/built"

# ── 1. what PyPI serves ──────────────────────────────────────────────────
if [ -n "${PYPI_DIST_DIR:-}" ]; then
  cp "$PYPI_DIST_DIR"/*.whl "$PYPI_DIST_DIR"/*.tar.gz "$work/pypi/" 2>/dev/null || die "no wheel and sdist in PYPI_DIST_DIR"
else
  curl -fsSL --retry 3 "https://pypi.org/pypi/${PACKAGE}/${VERSION}/json" -o "$work/pypi.json" \
    || die "cannot fetch the PyPI record for ${PACKAGE} ${VERSION}"
  python3 - "$work/pypi.json" > "$work/files.tsv" <<'PY' || die "the PyPI record for ${PACKAGE} ${VERSION} has no sdist and wheel"
import json, sys
urls = json.load(open(sys.argv[1]))["urls"]
want = {"sdist": None, "bdist_wheel": None}
for u in urls:
    if u["packagetype"] in want and want[u["packagetype"]] is None:
        want[u["packagetype"]] = u
if not all(want.values()):
    sys.exit(1)
for u in want.values():
    print(f'{u["filename"]}\t{u["url"]}\t{u["digests"]["sha256"]}')
PY
  while IFS=$'\t' read -r fname url digest; do
    [[ "$fname" =~ ^[A-Za-z0-9._+-]+$ ]] || die "unexpected file name '$fname' in the PyPI record"
    curl -fsSL --retry 3 "$url" -o "$work/pypi/$fname" || die "cannot download $fname"
    got="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$work/pypi/$fname")"
    [ "$got" = "$digest" ] || die "$fname sha256 is $got, PyPI states $digest"
  done < "$work/files.tsv"
fi

# ── 2. what the tag builds ───────────────────────────────────────────────
if [ -n "${BUILT_DIST_DIR:-}" ]; then
  cp "$BUILT_DIST_DIR"/*.whl "$BUILT_DIST_DIR"/*.tar.gz "$work/built/" 2>/dev/null || die "no wheel and sdist in BUILT_DIST_DIR"
  repack_live="${REPACK_LIVE:-no}"
else
  git clone -q --no-hardlinks "$REPO_URL" "$work/co" 2>"$work/err" || die "cannot clone $REPO_URL: $(head -c 200 "$work/err")"
  git -C "$work/co" rev-parse -q --verify "refs/tags/${TAG}^{commit}" >/dev/null || die "the repo has no tag ${TAG}"
  git -C "$work/co" checkout -q "${TAG}" 2>"$work/err" || die "cannot check out ${TAG}: $(head -c 200 "$work/err")"
  echo "tag ${TAG} is commit $(git -C "$work/co" rev-parse HEAD)"
  sde="$(git -C "$work/co" log -1 --format=%ct)"
  "$PYTHON" -m venv "$work/venv" || die "cannot create a venv with $PYTHON"
  "$work/venv/bin/pip" install -q --disable-pip-version-check build==1.6.1 >/dev/null 2>"$work/err" || die "cannot install build: $(head -c 200 "$work/err")"
  echo "building with $("$work/venv/bin/python" --version 2>&1), SOURCE_DATE_EPOCH=$sde"
  ( cd "$work/co" && SOURCE_DATE_EPOCH="$sde" "$work/venv/bin/python" -m build --sdist --wheel --outdir "$work/built" >"$work/build.log" 2>&1 ) \
    || { tail -15 "$work/build.log" >&2; die "the build of ${TAG} failed"; }
  if [ -f "$work/co/scripts/repack_sdist.sh" ]; then
    repack_live=yes
    ( cd "$work/co" && SOURCE_DATE_EPOCH="$sde" bash scripts/repack_sdist.sh "$work"/built/*.tar.gz ) || die "the tag's repack_sdist.sh failed"
  else
    repack_live=no
  fi
fi

# ── 3. compare content ───────────────────────────────────────────────────
one() {  # one <dir> <glob> : the single file, or refuse
  local -a f=("$1"/$2)
  [ -e "${f[0]}" ] && [ "${#f[@]}" -eq 1 ] || die "need exactly one $2 in $1, found ${#f[@]}"
  echo "${f[0]}"
}
pw="$(one "$work/pypi" '*.whl')";  bw="$(one "$work/built" '*.whl')"
ps="$(one "$work/pypi" '*.tar.gz')"; bs="$(one "$work/built" '*.tar.gz')"

mkdir "$work/cmp"
for side in pw bw; do mkdir "$work/cmp/wheel_$side" "$work/cmp/sdist_${side/w/s}"; done
python3 -m zipfile -e "$pw" "$work/cmp/wheel_pw" >/dev/null || die "cannot unpack the PyPI wheel"
python3 -m zipfile -e "$bw" "$work/cmp/wheel_bw" >/dev/null || die "cannot unpack the built wheel"
tar -xzf "$ps" -C "$work/cmp/sdist_ps" || die "cannot unpack the PyPI sdist"
tar -xzf "$bs" -C "$work/cmp/sdist_bs" || die "cannot unpack the built sdist"

problems=()
total=0
report=""
check_tree() {  # check_tree <label> <dir a> <dir b>
  local label="$1" a="$2" b="$3" na nb out rc=0
  na="$(find "$work/cmp/$a" -type f | wc -l | tr -d ' ')"
  nb="$(find "$work/cmp/$b" -type f | wc -l | tr -d ' ')"
  { [ "$na" -gt 0 ] && [ "$nb" -gt 0 ]; } || die "the $label unpacked to nothing (PyPI $na files, built $nb files)"
  out="$(cd "$work/cmp" && diff -rq "$a" "$b")" || rc=$?
  [ "$rc" -le 1 ] || die "diff failed on the $label (exit $rc)"
  report="${report}${label}: PyPI ${na} files, built ${nb} files. "
  if [ -n "$out" ]; then
    while IFS= read -r line; do
      case "$line" in
        "Files $a/"*" and $b/"*" differ") p="${line#Files $a/}"; p="${p%% and $b/*}" ;;
        "Only in $a"*) p="${line#Only in $a}"; p="${p#/}"; p="${p/: //}"; p="$p (only in PyPI)" ;;
        "Only in $b"*) p="${line#Only in $b}"; p="${p#/}"; p="${p/: //}"; p="$p (only in the rebuild)" ;;
        *) p="$line" ;;
      esac
      problems+=("$label: $p"); total=$((total + 1))
    done <<< "$out"
  fi
}
check_tree wheel wheel_pw wheel_bw
check_tree sdist sdist_ps sdist_bs
[ "$(basename "$pw")" = "$(basename "$bw")" ] || { problems+=("wheel: filename ($(basename "$pw") against $(basename "$bw"))"); total=$((total + 1)); }
[ "$(basename "$ps")" = "$(basename "$bs")" ] || { problems+=("sdist: filename ($(basename "$ps") against $(basename "$bs"))"); total=$((total + 1)); }

if [ "$total" -gt 0 ]; then
  echo "release_postcondition: FAIL ${PACKAGE} ${VERSION}: ${total} differing paths, first 5 shown" >&2
  for p in "${problems[@]:0:5}"; do echo "DIFF $p" >&2; done
  exit 1
fi

sha() { python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }
echo "release_postcondition: content equal for ${PACKAGE} ${VERSION}. ${report}"
echo "wheel sha256 (information, never judged): PyPI $(sha "$pw") built $(sha "$bw")"
sp="$(sha "$ps")"; sb="$(sha "$bs")"
if [ "$repack_live" = "yes" ]; then
  if [ "$sp" = "$sb" ]; then
    echo "sdist sha256: equal $sp"
  else
    echo "release_postcondition: FAIL ${PACKAGE} ${VERSION}: sdist sha256 differs although the tag carries scripts/repack_sdist.sh, PyPI $sp built $sb" >&2
    exit 1
  fi
else
  echo "sdist sha256: NOT APPLICABLE (the tag has no scripts/repack_sdist.sh), information only: PyPI $sp built $sb"
fi
echo "release_postcondition: PASS"
