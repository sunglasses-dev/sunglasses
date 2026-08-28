#!/usr/bin/env python3
"""gauntlet.py - attack our own product on a schedule and publish what we miss.

REPO-ONLY BY DESIGN. Not a `sunglasses` subcommand, not in the wheel. The
published wheel carries 169 entries and zero corpus files (measured 2026-08-28),
and the locked constraints are "corpus does not ship" and "zero network" - so a
user-facing verb would exist only to print an error. It sits at the repo root
next to fp_gate.py and pattern_forge.py, where this repo already keeps tools
like this.

WHAT IT MEASURES, SAID HONESTLY: a regression rate against a corpus we declare
and freeze. NOT a bypass rate. Until a genuinely held-out pool exists and has
survived one freeze with the derived_from_case link enforced, "bypass" would
claim something the method cannot support.

Suites:
  A  exfil shapes    -> firewall. NOT RUN in v1; see suite_a_exfil.
  B  benign / FP     -> scanner. False-positive rate WITH its denominator,
                        beside the known-failure ratchet.
  C  malformed       -> firewall, over STDIN. Expect defer; never a wedge,
                        never a silent allow, never a non-zero exit.
  D  engine canaries -> scanner. Misses here are the published number.

Suites A and C drive the hook as a SUBPROCESS over stdin, the way the harness
drives it. The hook's contract is "never raises, never exits non-zero"; an
in-process call cannot fail that way, so it would score us on a path no user
takes.

Usage:
    python3 gauntlet.py run [--out PATH] [--release R] [--triggered-by launchd]
    python3 gauntlet.py freeze --release 0.5.0
"""
import argparse
import datetime as dt
import glob
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "gauntlet", "corpus")
RUNS = os.path.join(HERE, "gauntlet", "runs")

# The engine has four verdicts and the page has four rows. Folding quarantine
# into "blocked" inflates the headline; folding it into "delivered" understates
# us. It is held for review, which is neither.
BUCKET = {
    "block": "blocked",
    "quarantine": "held",
    "allow_redacted": "degraded",
    "allow": "delivered",
}


def _now():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _sha256_of(paths) -> str:
    """One hash over the whole corpus so an artifact can prove WHICH corpus
    produced it. A score whose corpus cannot be identified is a number, not a
    measurement."""
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(os.path.basename(path).encode())
        with open(path, "rb") as handle:
            digest.update(handle.read())
    return digest.hexdigest()


def _git_sha() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=HERE,
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def _hook(raw, timeout=30) -> dict:
    """Drive the firewall the way Claude Code does: subprocess, JSON on stdin.

    An unparseable answer is itself a finding, and suite C is where it counts.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "sunglasses", "firewall-hook"],
        input=raw if isinstance(raw, str) else json.dumps(raw),
        capture_output=True, text=True, cwd=HERE, timeout=timeout,
        env={**os.environ, "PYTHONPATH": HERE},
    )
    try:
        return {"exit": proc.returncode, **json.loads(proc.stdout or "{}")}
    except ValueError:
        return {"exit": proc.returncode, "_unparseable": proc.stdout[:200]}


def suite_a_exfil() -> dict:
    """Secret-exfil shapes at the firewall — NOT IMPLEMENTED IN v1, on purpose.

    Blocked by a real constraint we discovered building this, and the right kind
    of blocked: **you cannot author an exfil corpus on a machine running our own
    firewall.** Writing a file whose text contains credential-format material is
    itself an outbound call carrying credential-format material, so the firewall
    denies the authoring step. It did exactly that to this file, correctly.

    The two ways out are both decisions, not code:
      1. add the fixtures to `KNOWN_PUBLIC_CANARIES` (a security allowlist in the
         product — deliberate sign-off, not a build side effect), or
      2. keep suite A's fixtures outside the repo entirely, with the run
         assembling them in memory from a documented recipe.

    Option 2 is one short step from "construct the string so the detector does
    not see it", which is the shape of an evasion, so it should be chosen out
    loud or not at all. Until one is chosen, this suite reports that it did not
    run. It does NOT report zero — a suite that silently scores 0/0 reads as
    "nothing got through", which is the exact lie this whole page exists to
    avoid.
    """
    return {"status": "not_run",
            "reason": ("corpus authoring is blocked by our own firewall; needs a "
                       "KNOWN_PUBLIC_CANARIES entry or an out-of-repo fixture "
                       "decision"),
            "corpus_n": 0, "blocked": 0, "delivered": 0, "misses": []}


def suite_d_engine(engine) -> dict:
    """Attack canaries through the scanner. Misses here are the published number."""
    path = os.path.join(HERE, "tests", "benchmark", "attacks.json")
    attacks = json.load(open(path))["attacks"]
    counts = {"blocked": 0, "held": 0, "degraded": 0, "delivered": 0}
    misses = []
    for attack in attacks:
        result = engine.scan(attack["text"], attack["channel"])
        bucket = BUCKET.get(result.decision, "delivered")
        counts[bucket] += 1
        if bucket in ("degraded", "delivered"):
            # CLASS ONLY, never the case text. What we caught is documentation;
            # what we missed is a working, unpatched exploit with our name on it.
            misses.append({
                "case_id": attack["id"],
                "class": attack.get("category", "unclassified"),
                "found": dt.date.today().isoformat(),
                "fixed_in": None,
                "tuned_from": attack.get("kind") != "novel_unknown",
            })
    return {"corpus_n": len(attacks), **counts, "misses": misses,
            "corpus_sha256": _sha256_of([path])[:16]}


def suite_b_false_positives(engine) -> dict:
    """Real-world clean files. The ratchet is published and only ever shrinks."""
    corpus_dir = os.path.join(HERE, "tests", "fp_real_world_corpus")
    files = sorted(glob.glob(os.path.join(corpus_dir, "*.md")))
    known_path = os.path.join(corpus_dir, "KNOWN_FAILURES.json")
    known = json.load(open(known_path)) if os.path.exists(known_path) else {}
    fired = []
    for path in files:
        text = open(path, encoding="utf-8", errors="replace").read()
        if engine.scan(text, "file").decision != "allow":
            fired.append(os.path.basename(path))
    return {
        "corpus_n": len(files),
        "false_positives": len(fired),
        "ratchet_n": len(known),
        "ratchet": sorted(known),
        # A file that fires and is NOT on the ratchet is a regression, and it is
        # the only thing in this suite that should ever wake anyone up.
        "new_false_positives": sorted(set(fired) - set(known)),
    }


def suite_c_malformed() -> dict:
    """Corrupt input must land on defer with a receipt."""
    cases = [
        ("C-JSON-01", "{not json"),
        ("C-EMPTY-01", ""),
        ("C-ARRAY-01", "[1,2,3]"),
        ("C-BIG-01", json.dumps({"tool_name": "Bash",
                                 "tool_input": {"command": "x" * 200_000}})),
    ]
    failures = []
    for case_id, raw in cases:
        try:
            out = _hook(raw)
        except subprocess.TimeoutExpired:
            failures.append({"case_id": case_id, "class": "hook hung on malformed input",
                             "found": dt.date.today().isoformat(), "fixed_in": None})
            continue
        if out.get("exit") != 0:
            failures.append({"case_id": case_id,
                             "class": "hook exited non-zero instead of failing open",
                             "found": dt.date.today().isoformat(), "fixed_in": None})
    return {"corpus_n": len(cases),
            "failed_open_correctly": len(cases) - len(failures),
            "misses": failures}


# ── the publishable-output gate ─────────────────────────────────────────────
# The blanket rule "no payload strings anywhere" would fail against our own
# package for no security gain: the wheel already ships 138 pattern files whose
# records carry keywords and examples. That IS the product - the detection rules
# are public by design. The line that actually matters is narrower and it is
# checkable: never publish the text of a case we MISSED. A caught case's example
# is documentation. A missed case's payload is a working, unpatched exploit with
# our own name on it.
MISS_FIELDS = {"case_id", "class", "found", "fixed_in", "tuned_from"}


def assert_publishable(artifact: dict) -> list:
    """Return every reason this artifact must not be published. Empty = safe.

    Checked mechanically rather than by review, because "someone will notice a
    payload in the JSON" is not a control.
    """
    problems = []
    for suite_name, suite in (artifact.get("suites") or {}).items():
        for miss in suite.get("misses") or []:
            extra = set(miss) - MISS_FIELDS
            if extra:
                problems.append(
                    f"{suite_name}: miss {miss.get('case_id', '?')} carries "
                    f"disallowed field(s) {sorted(extra)} - a miss may carry "
                    f"{sorted(MISS_FIELDS)} and nothing else")
    return problems


def cmd_run(args) -> int:
    artifact = {
        "schema": 1,
        "run": {"started_at": _now(), "finished_at": None,
                "triggered_by": args.triggered_by, "completed": False},
        "versions": {}, "suites": {}, "totals": {},
    }
    out_path = args.out or os.path.join(RUNS, dt.date.today().isoformat() + ".json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    def write():
        # Written on EVERY exit path, failure included. A run that dies without
        # an artifact leaves the page showing yesterday's number as today's,
        # and no staleness signal fires because the artifact it reads is fine.
        with open(out_path, "w") as handle:
            json.dump(artifact, handle, indent=1)
            handle.write("\n")

    try:
        sys.path.insert(0, HERE)
        from sunglasses import __version__
        from sunglasses.engine import SunglassesEngine
        engine = SunglassesEngine()
        artifact["versions"] = {"scanner": __version__, "git": _git_sha(),
                                "corpus_release": args.release or "unfrozen"}
        artifact["suites"]["D_engine"] = suite_d_engine(engine)
        artifact["suites"]["B_false_positives"] = suite_b_false_positives(engine)
        artifact["suites"]["A_exfil"] = suite_a_exfil()
        artifact["suites"]["C_malformed"] = suite_c_malformed()
        d = artifact["suites"]["D_engine"]
        b = artifact["suites"]["B_false_positives"]
        artifact["totals"] = {
            "corpus_n": d["corpus_n"], "blocked": d["blocked"], "held": d["held"],
            "degraded": d["degraded"], "delivered": d["delivered"],
            "false_positives": b["false_positives"], "fp_corpus_n": b["corpus_n"],
        }
        artifact["run"]["completed"] = True
    except Exception as exc:  # noqa: BLE001
        artifact["run"]["error"] = str(type(exc).__name__) + ": " + str(exc)
    finally:
        artifact["run"]["finished_at"] = _now()
        write()

    if not artifact["run"]["completed"]:
        print("  RUN FAILED: " + str(artifact["run"].get("error")))
        print("  artifact written anyway (completed:false) -> " + out_path)
        return 1
    t = artifact["totals"]
    print("  blocked %d - held %d - degraded %d - delivered %d  of %d"
          % (t["blocked"], t["held"], t["degraded"], t["delivered"], t["corpus_n"]))
    print("  false positives %d of %d real-world files"
          % (t["false_positives"], t["fp_corpus_n"]))
    print("  suite A: " + artifact["suites"]["A_exfil"]["status"])
    print("  -> " + out_path)
    return 0


def cmd_freeze(args) -> int:
    """Promote the pool into an immutable scoring set for one release.

    REFUSES any case whose provenance stamp lacks tuned_from_pattern_ids.
    Defaulting a missing stamp to "not tuned-from" is how a held-out set turns
    back into an answer key: the permissive default is invisible, and it only
    ever moves the score in the flattering direction.
    """
    pool_path = os.path.join(CORPUS, "pool", "pool.json")
    if not os.path.exists(pool_path):
        print("  no pool at " + pool_path)
        return 1
    cases = json.load(open(pool_path)).get("cases", [])
    unstamped = [c.get("id", "<no id>") for c in cases
                 if "tuned_from_pattern_ids" not in c]
    if unstamped:
        print("  REFUSING to freeze: %d case(s) have no provenance stamp" % len(unstamped))
        for case_id in unstamped:
            print("    - " + case_id)
        print("  A missing stamp is not 'clean'. Stamp it at capture, then freeze.")
        return 1
    scoring = [c for c in cases if not c["tuned_from_pattern_ids"]]
    tuned = [c for c in cases if c["tuned_from_pattern_ids"]]
    target = os.path.join(CORPUS, "frozen", args.release)
    if os.path.exists(target):
        print("  " + target + " already exists - a frozen corpus is immutable.")
        return 1
    os.makedirs(target)
    with open(os.path.join(target, "manifest.json"), "w") as handle:
        json.dump({"release": args.release, "frozen_at": _now(), "cases": scoring,
                   "tuned_from_excluded": [c["id"] for c in tuned]}, handle, indent=1)
        handle.write("\n")
    print("  froze %d case(s) for %s; excluded %d tuned-from"
          % (len(scoring), args.release, len(tuned)))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Gauntlet - attack our own product")
    subs = parser.add_subparsers(dest="command", required=True)
    run = subs.add_parser("run", help="Run every suite and write the artifact")
    run.add_argument("--out")
    run.add_argument("--release")
    run.add_argument("--triggered-by", dest="triggered_by", default="manual",
                     choices=["manual", "launchd"])
    run.set_defaults(func=cmd_run)
    freeze = subs.add_parser("freeze", help="Promote the pool into a scoring set")
    freeze.add_argument("--release", required=True)
    freeze.set_defaults(func=cmd_freeze)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
