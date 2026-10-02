#!/usr/bin/env bash
# Repack one sdist so its bytes depend on the tagged commit and on nothing else.
#
# usage: SOURCE_DATE_EPOCH=<seconds> scripts/repack_sdist.sh dist/<name>.tar.gz
#
# setuptools ignores SOURCE_DATE_EPOCH for the sdist. Builds of one commit give
# the same member names, order, modes and file bytes, and differ in three
# things only: member mtimes, the gzip header time and the owner ids (a CI
# runner is 1001, a laptop is 501). This rewrites those three and nothing else:
#
#   tar --sort=name --mtime=@SOURCE_DATE_EPOCH --owner=0 --group=0 --numeric-owner, then gzip -n
#
# --format=gnu because the posix (pax) format writes a header named after the
# tar process id, which is a new difference on every run. LC_ALL=C pins the sort.
# The archive is extracted with -p so modes survive. Before the original is
# replaced, a python check compares names, modes, sizes, types and file bytes
# before and after, and checks that every mtime is SOURCE_DATE_EPOCH, every
# owner is 0 and the gzip header time is 0. Any failure leaves the input alone.
set -euo pipefail
export LC_ALL=C

die() { echo "repack_sdist: REFUSED: $*" >&2; exit 2; }

[ $# -eq 1 ] || die "usage: repack_sdist.sh dist/<name>.tar.gz"
src="$1"
case "$src" in *.tar.gz) ;; *) die "$src is not a .tar.gz" ;; esac
[ -f "$src" ] || die "$src does not exist"
[[ "${SOURCE_DATE_EPOCH:-}" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH must be a whole number of seconds, got '${SOURCE_DATE_EPOCH:-}'"
tar --version 2>&1 | head -1 | grep -q 'GNU tar' || die "this needs GNU tar (bsdtar has no --sort and a pax repack is not reproducible)"
command -v gzip >/dev/null || die "gzip not found"

work="$(mktemp -d)"
staged=""
cleanup() { rm -rf "$work"; [ -z "$staged" ] || rm -f "$staged"; }
trap cleanup EXIT

mkdir "$work/x"
tar -xzpf "$src" -C "$work/x" --no-same-owner 2>"$work/err" || die "cannot read $src as a gzip tar: $(head -c 200 "$work/err")"
tops=("$work"/x/*)
[ "${#tops[@]}" -eq 1 ] && [ -d "${tops[0]}" ] || die "$src must hold exactly one top directory"
top="$(basename "${tops[0]}")"

tar --format=gnu --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner \
    -C "$work/x" -cf - "$top" | gzip -n -9 > "$work/out.tar.gz"

SRC="$src" OUT="$work/out.tar.gz" python3 - <<'PY'
import hashlib, os, stat, sys, tarfile

sde = int(os.environ["SOURCE_DATE_EPOCH"])

def read(path):
    out = {}
    with tarfile.open(path, "r:gz") as tf:
        for m in tf.getmembers():
            data = tf.extractfile(m).read() if m.isfile() else None
            out[m.name] = (stat.S_IMODE(m.mode), m.size, m.type, m.linkname,
                           hashlib.sha256(data).hexdigest() if data is not None else None)
    return out

before, after = read(os.environ["SRC"]), read(os.environ["OUT"])
if not before:
    sys.exit("repack_sdist: REFUSED: the input archive has no members")
if before != after:
    missing = sorted(set(before) ^ set(after))[:5]
    changed = sorted(n for n in before if n in after and before[n] != after[n])[:5]
    sys.exit(f"repack_sdist: REFUSED: the repack changed content, names {missing} entries {changed}")
with open(os.environ["OUT"], "rb") as fh:
    head = fh.read(10)
if head[:2] != b"\x1f\x8b" or head[4:8] != b"\x00\x00\x00\x00":
    sys.exit("repack_sdist: REFUSED: the gzip header time is not zero")
with tarfile.open(os.environ["OUT"], "r:gz") as tf:
    ms = tf.getmembers()
    names = [m.name for m in ms]
    # GNU tar sorts each directory by name and walks depth first, so the order is
    # the path split into components, not the flat string.
    if names != sorted(names, key=lambda n: tuple(n.split("/"))):
        sys.exit("repack_sdist: REFUSED: members are not in sorted tree order")
    for m in ms:
        if m.mtime != sde or m.uid != 0 or m.gid != 0 or m.uname or m.gname or m.pax_headers:
            sys.exit(f"repack_sdist: REFUSED: {m.name} still carries mtime {m.mtime} uid {m.uid} gid {m.gid} owner '{m.uname}:{m.gname}' pax {bool(m.pax_headers)}")
print(f"repack_sdist: {len(ms)} members, content equal before and after, mtime {sde}, owner 0:0, gzip time 0")
PY

staged="$(mktemp "${src}.XXXXXX")"
cat "$work/out.tar.gz" > "$staged"
chmod "$(stat -c %a "$src")" "$staged"   # mktemp makes it 0600, the sdist keeps the mode it had
mv -f "$staged" "$src"
staged=""
python3 -c 'import hashlib,sys; print("repack_sdist: sha256 " + hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest() + "  " + sys.argv[1])' "$src"
