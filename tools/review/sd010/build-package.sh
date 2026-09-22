#!/bin/zsh
# Build a review package for GLS-SD-010-EMB from two git refs.
#
#   tools/review/sd010/build-package.sh <head-ref> <base-ref> [out-dir]
#
# WHY THIS EXISTS. Rounds 1 to 4 each ran from a package hand-assembled in a
# tmp directory, so the harness that produced every verdict lived nowhere and
# a later reader could not rebuild what was reviewed. The probes are now in the
# repo beside the rule they grade; this is what turns them back into a package.
#
# THE ARCHIVES ARE VERIFIED, NOT TRUSTED: the file list of each extracted tree
# is compared against `git ls-tree` for its ref, symlinks included (an early
# version used `find -type f`, reported MISMATCH on three symlinked fixtures,
# and was itself the defect). Caches are excluded, because a stray
# __pycache__ inflated the counts a reviewer then measured against §2 and
# rightly called out.
set -eu
HEAD_REF=${1:?head ref}; BASE_REF=${2:?base ref}
ROOT=$(git rev-parse --show-toplevel)
SHORT=$(git -C "$ROOT" rev-parse --short "$HEAD_REF")
OUT=${3:-/private/tmp/SD010_EMB_REVIEW_${SHORT}_$(date +%Y-%m-%d)}
rm -rf "$OUT"; mkdir -p "$OUT/head" "$OUT/base" "$OUT/probes"
git -C "$ROOT" archive "$HEAD_REF" | tar -x -C "$OUT/head"
git -C "$ROOT" archive "$BASE_REF" | tar -x -C "$OUT/base"
cp "$ROOT"/tools/review/sd010/_*.py "$ROOT"/tools/review/sd010/p*.sh "$OUT/probes/"
rm -rf "$OUT/probes/__pycache__"
find "$OUT/head" "$OUT/base" \( -name __pycache__ -o -name .pytest_cache \) -type d -prune -exec rm -rf {} + 2>/dev/null || true

fail=0
# One function, called twice with explicit arguments. An earlier version packed
# "ref:dir" into a loop variable and split it with ${x%%:*}; it mis-split under
# zsh and tried to archive a ref called ".ead". Clever beat correct, so it is
# gone -- a package builder that silently archives the wrong ref would hand a
# reviewer the wrong tree with a confident banner over it.
verify_tree() {
  ref="$1"; dir="$2"
  want=$(git -C "$ROOT" ls-tree -r --name-only "$ref" | sort | shasum | cut -d' ' -f1)
  got=$(cd "$OUT/$dir" && find . \( -type f -o -type l \) | sed 's|^\./||' | sort | shasum | cut -d' ' -f1)
  n=$(git -C "$ROOT" ls-tree -r --name-only "$ref" | wc -l | tr -d ' ')
  if [ "$want" = "$got" ]; then
    echo "  $dir ($(git -C "$ROOT" rev-parse --short "$ref")): $n files, list IDENTICAL to the commit"
  else
    echo "  $dir ($ref): *** MISMATCH -- do not review this package ***"
    fail=1
  fi
}
verify_tree "$HEAD_REF" head
verify_tree "$BASE_REF" base
[ "$fail" -eq 0 ] || exit 1
echo "  head sha256 $(shasum -a256 "$OUT/head/sunglasses/patterns.py" | cut -c1-16)"
echo "  base sha256 $(shasum -a256 "$OUT/base/sunglasses/patterns.py" | cut -c1-16)"
mkdir -p "$OUT/logs"
python3 "$OUT/probes/_build_mutants.py" "$OUT"
echo "package: $OUT"
