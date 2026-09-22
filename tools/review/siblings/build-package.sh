#!/bin/zsh
# Build a review package for the tool-metadata `-API` siblings from two git refs.
#
#   tools/review/siblings/build-package.sh <head-ref> <base-ref> [out-dir]
#
# WHY THIS EXISTS, and it is the same reason the sd010 one does. Round 1's
# package was hand-assembled in a tmp directory, so the harness that produced
# the verdict lived nowhere and a later reader could not rebuild what was
# reviewed. Worse here: the probes were FIXED after that package was built, so
# the staged copy graded the rules with the weaknesses review had already found.
#
# THE ARCHIVES ARE VERIFIED, NOT TRUSTED: the file list of each extracted tree
# is diffed against `git ls-tree` for its ref, symlinks included. Caches are
# stripped, because running a probe inside `head/` leaves __pycache__ and a
# reviewer then measures an inflated count against the manifest.
#
# THE OUT DIR IS `/tmp`, NEVER `/private/tmp`. The reviewer's editor rejects the
# resolved spelling as outside the project while its shell accepts it, which
# cost a whole round: every probe ran clean and the verdict could not be
# written. Same directory, different answer.
set -eu
HEAD_REF=${1:?head ref}; BASE_REF=${2:?base ref}
ROOT=$(git rev-parse --show-toplevel)
SHORT=$(git -C "$ROOT" rev-parse --short "$HEAD_REF")
OUT=${3:-/tmp/SIBLINGS_REVIEW_${SHORT}_$(date +%Y-%m-%d)}
rm -rf "$OUT"; mkdir -p "$OUT/head" "$OUT/base" "$OUT/probes" "$OUT/logs"
git -C "$ROOT" archive "$HEAD_REF" | tar -x -C "$OUT/head"
git -C "$ROOT" archive "$BASE_REF" | tar -x -C "$OUT/base"
cp "$ROOT"/tools/review/siblings/_*.py "$ROOT"/tools/review/siblings/p*.sh "$OUT/probes/"
# regex_sample lives with the tests and the probes import it by name
cp "$ROOT"/tests/regex_sample.py "$OUT/probes/" 2>/dev/null || true
rm -rf "$OUT/probes/__pycache__"
find "$OUT/head" "$OUT/base" \( -name __pycache__ -o -name .pytest_cache \) -type d -prune -exec rm -rf {} + 2>/dev/null || true

fail=0
verify_tree() {
  ref="$1"; dir="$2"
  want=$(git -C "$ROOT" ls-tree -r --name-only "$ref" | LC_ALL=C sort)
  got=$(cd "$OUT/$dir" && find . \( -type f -o -type l \) | sed 's|^\./||' | LC_ALL=C sort)
  n=$(printf '%s\n' "$want" | wc -l | tr -d ' ')
  if [ "$want" = "$got" ]; then
    echo "  $dir ($(git -C "$ROOT" rev-parse --short "$ref")): $n files, list IDENTICAL to the commit"
  else
    echo "  $dir ($ref): *** MISMATCH -- do not review this package ***"; fail=1
  fi
}
verify_tree "$HEAD_REF" head
verify_tree "$BASE_REF" base
[ "$fail" -eq 0 ] || exit 1
echo "  head sha256 $(shasum -a256 "$OUT/head/sunglasses/patterns.py" | cut -c1-16)"
echo "package: $OUT"
