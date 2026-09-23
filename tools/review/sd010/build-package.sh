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
# THE SPELLING IS LOAD-BEARING: `/tmp`, never `/private/tmp`. codex runs the
# reviewer with `sandbox: workspace-write [workdir, /tmp, $TMPDIR]`, and that
# writable root is matched as the LITERAL STRING `/tmp`. Hand it the resolved
# spelling and its SHELL still works -- it will happily run a probe in there --
# but its EDITOR refuses the path as "outside of the project", so a reviewer can
# run every probe and still be unable to write a verdict. Round 5 was REFUSED
# for exactly that and nothing else; the round eleven minutes later wrote fine
# because it happened to use `/tmp`. Same directory (`/tmp -> private/tmp`),
# different answer, and leaving the spelling to chance is what turned a bug
# into a coin flip.
OUT=${3:-/tmp/SD010_EMB_REVIEW_${SHORT}_$(date +%Y-%m-%d)}
rm -rf "$OUT"; mkdir -p "$OUT/head" "$OUT/base" "$OUT/probes"
git -C "$ROOT" archive "$HEAD_REF" | tar -x -C "$OUT/head"
git -C "$ROOT" archive "$BASE_REF" | tar -x -C "$OUT/base"
# THE HARNESS COMES FROM THE EXTRACTED HEAD TREE, never from the checkout this
# script runs in (the siblings builder had the same defect; ASTRA found it in
# round 2 there). A rebuild from another checkout must grade the same refs with
# the same probes, or the package is not what it says it is.
H="$OUT/head/tools/review/sd010"
for need in "$H/_common.py" "$H/_build_variants.py" "$H/MANIFEST.template.md" "$H/VERDICT.template.md"; do
  [ -f "$need" ] || { echo "REFUSED: $HEAD_REF has no ${need#$OUT/head/} -- the harness must come from the ref under review" >&2; exit 3; }
done
cp "$H"/_*.py "$H"/p*.sh "$OUT/probes/"
# The variant builder is NOT a probe. It holds the rule fragments each variant
# tree removes, the reviewer never needs to run it, and the channel it reads
# through filters on exactly that kind of text. It runs from head/ below.
rm -f "$OUT/probes/_build_variants.py"
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
python3 "$H/_build_variants.py" "$OUT"
# MANIFEST.md and VERDICT.md are EMITTED, not hand-written. On 2026-09-23 the
# Mac rebooted, /tmp went with it, and the only copies of both were in /tmp:
# the round had to be reconstructed from the reviewer's own logs. Now every
# byte of a package comes from the ref plus this script.
HS=$(git -C "$ROOT" rev-parse --short "$HEAD_REF"); BS=$(git -C "$ROOT" rev-parse --short "$BASE_REF")
NH=$(git -C "$ROOT" ls-tree -r --name-only "$HEAD_REF" | wc -l | tr -d ' ')
NB=$(git -C "$ROOT" ls-tree -r --name-only "$BASE_REF" | wc -l | tr -d ' ')
PS=$(shasum -a256 "$OUT/head/sunglasses/patterns.py" | cut -c1-16)
for t in MANIFEST VERDICT; do
  sed -e "s|@HEAD@|$HS|g" -e "s|@BASE@|$BS|g" -e "s|@HEAD_FILES@|$NH|g" \
      -e "s|@BASE_FILES@|$NB|g" -e "s|@PATTERNS_SHA@|$PS|g" -e "s|@OUT@|$OUT|g" \
      "$H/$t.template.md" > "$OUT/$t.md"
  if grep -q "@[A-Z_]*@" "$OUT/$t.md"; then echo "REFUSED: $t.md has an unfilled placeholder" >&2; exit 4; fi
done
echo "package: $OUT"
