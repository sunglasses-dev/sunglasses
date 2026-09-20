"""ROW 1 of the three-roots work, and it runs BEFORE anything else changes.

Every item in that PR sits next to the approval gate, and `serve.build_route`
says in its own docstring that opening the gate is the one change that would
make the rest decorative. So the gate's refusals get a battery of their own
first: each mutation below RELAXES `may_call` in one specific way, and each must
die by the control that names it.

A relaxation here is not a bug that shows up as a wrong answer. It is a call
forwarded to a server nobody approved, with a clean receipt attached.

    python3 tests/proxy/mutate_approvals.py
"""
import atexit
import hashlib
import os
import pathlib
import shutil
import tempfile
import subprocess
import sys

# THE TREE THIS MUTATES IS A PRIVATE COPY, and that is the whole of this block.
#
# Until 2026-09-19 the harness rewrote `sunglasses/proxy/approvals.py` IN PLACE. Two things
# followed, and both were paid for on the same night:
#
#   * a kill STRANDS A MUTANT. Interrupt the run between the write and the
#     restore -- a platform budget cut, a Ctrl-C, an OOM -- and the working tree
#     keeps a mutated product. The next battery then refuses with BASELINE IS
#     RED, and that is the LUCKY case; the unlucky one is a reader that trusts
#     the file.
#   * it rewrites a tree OTHER PROCESSES READ. A reviewer working in the same
#     directory saw a mutated product mid-review and its round was void.
#
# So: copy the tree once, mutate the copy, point pytest at the copy. The real
# source is opened for reading and never for writing, and `_assert_source_untouched`
# proves that rather than asserting it in a comment.
SOURCE_ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE_TARGET = SOURCE_ROOT / "sunglasses/proxy/approvals.py"


def _digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


_SOURCE_DIGEST_AT_START = _digest(SOURCE_TARGET)


def _assert_source_untouched(when):
    """Refuse LOUDLY if the real product moved while we ran.

    A silent mismatch is how the in-place version did its damage: nothing said
    anything until a later run found a red baseline and had to work backwards.
    """
    now = _digest(SOURCE_TARGET)
    if now != _SOURCE_DIGEST_AT_START:
        raise SystemExit(
            f"REFUSING: {SOURCE_TARGET} changed {when} this battery "
            f"({_SOURCE_DIGEST_AT_START[:16]} -> {now[:16]}). This harness "
            f"mutates a private copy and must never write the source tree.")


def _sweep_abandoned_copies(prefix, keep_hours=6):
    """Remove OUR OWN older copies, because an uncatchable kill skips `atexit`.

    The copy costs about 18 MB. A kill -9 -- which is exactly the case this
    harness now survives -- leaves it behind, so without this the fix trades a
    corrupted source tree for an unbounded pile of temp trees. The age floor is
    what keeps a CONCURRENT battery safe: a run younger than `keep_hours` is
    never touched, so two harnesses can run at once without eating each other.
    """
    import time
    root = pathlib.Path(tempfile.gettempdir())
    cutoff = time.time() - keep_hours * 3600
    for stale in root.glob(prefix + "*"):
        try:
            if stale.is_dir() and stale.stat().st_mtime < cutoff:
                shutil.rmtree(stale, ignore_errors=True)
        except OSError:
            pass

_sweep_abandoned_copies("mutate-approvals-")
_WORK = pathlib.Path(tempfile.mkdtemp(prefix="mutate-approvals-")) / "tree"
shutil.copytree(SOURCE_ROOT, _WORK,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
atexit.register(shutil.rmtree, _WORK.parent, True)

ROOT = _WORK
TARGET = ROOT / "sunglasses/proxy/approvals.py"
SUITE = "tests/test_proxy_approvals.py"

# (id, the defect, old source, mutated source, the control that must fail)
MUTATIONS = [
    ('GATE-BLOCKED', 'a blocked store still authorises calls',
     '    def may_call(self, tool_name, descriptor_sha256):\n        with self._lock:\n            blocked = self._blocked()\n            if blocked:\n                return blocked',
     '    def may_call(self, tool_name, descriptor_sha256):\n        with self._lock:\n            blocked = self._blocked()\n            if False:\n                return blocked',
     'test_a_failed_reactivation_of_a_live_approval_remembers_why'),

    ('GATE-REVOKED', 'an approval outlives the record that justified it',
     '            if record.get("snapshot_sha256") != self._active["snapshot"]:\n                self._active = None\n                return DESCRIPTOR_CHANGED',
     '            if False:\n                self._active = None\n                return DESCRIPTOR_CHANGED',
     'test_a_live_activation_does_not_outlive_the_record_it_was_granted_from'),

    ('GATE-UNNAMED-TOOL', 'a tool the capture never named is callable',
     '            entry = self._active["tools"].get(tool_name)\n            if entry is None:\n                return DESCRIPTOR_CHANGED',
     '            entry = self._active["tools"].get(tool_name)\n            if entry is None:\n                return None',
     'test_an_approved_call_needs_the_tool_and_its_descriptor_sha'),

    ('GATE-DESCRIPTOR', 'a tool whose descriptor moved is still callable',
     '            if entry.get("descriptor_sha256") != descriptor_sha256:\n                return DESCRIPTOR_CHANGED',
     '            if False:\n                return DESCRIPTOR_CHANGED',
     'test_an_approved_call_needs_the_tool_and_its_descriptor_sha'),

    # GATE-UNREADABLE IS DELIBERATELY ABSENT, and this note is the reason.
    # Removing `if bad or record is None` inside `may_call` changes no reachable
    # behaviour: `_blocked()` already answers SCAN_EXCEPTION for a bad record and
    # APPROVAL_REQUIRED when there is none, so the second check is defence in
    # depth and the mutant is EQUIVALENT. Written down here rather than left as
    # an open survivor in a report, which is the convention `route.py` uses for
    # the same shape at `may_deliver_list`.
]

def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(
        [sys.executable, "-B", "-m", "pytest", *SUITE.split(), "-q", "--no-header",
         "-p", "no:cacheprovider"],
        cwd=str(ROOT), env=env, capture_output=True, text=True)


def main():
    _assert_source_untouched("before the baseline")
    original = TARGET.read_text()

    base = run()
    if base.returncode != 0:
        print("BASELINE IS RED. A kill count on a red suite is not a kill count.")
        print(base.stdout[-2500:])
        return 1
    print(f"baseline GREEN — {base.stdout.strip().splitlines()[-1]}\n")

    killed, survived = [], []
    for mid, why, old, new, control in MUTATIONS:
        hits = original.count(old)
        if hits != 1:
            print(f"  {mid:12} ANCHOR LOST ({hits} matches) — proves nothing")
            survived.append((mid, why, f"anchor x{hits}"))
            continue
        TARGET.write_text(original.replace(old, new))
        try:
            r = run()
        finally:
            TARGET.write_text(original)

        fails = [l.split("::")[-1].split()[0].split("[")[0]
                 for l in r.stdout.splitlines() if l.startswith("FAILED")]
        if r.returncode != 0 and control in fails:
            print(f"  {mid:12} KILLED by {control}  ({len(fails)} failed)")
            killed.append(mid)
        elif r.returncode != 0:
            print(f"  {mid:12} red but NOT by {control} — fails: {sorted(set(fails))[:3]}")
            survived.append((mid, why, "wrong control"))
        else:
            print(f"  {mid:12} SURVIVOR — {why}")
            survived.append((mid, why, "survived"))

    assert TARGET.read_text() == original, "target not restored"
    _assert_source_untouched("after the last mutant")
    print(f"\nkilled {len(killed)}/{len(MUTATIONS)}")
    if survived:
        print("\nSURVIVORS (each one is a gap):")
        for mid, why, how in survived:
            print(f"  {mid}: {why}  [{how}]")
        return 1
    print("every mutation killed by its own control")
    return 0


if __name__ == "__main__":
    sys.exit(main())
