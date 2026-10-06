"""Drive every drivable variant on the harness stand in route and write what happened.

This is the INSTRUMENT. `produce.py` is the supervisor and it never calls this file:
the producer reads the run document this writes, the same way it reads the examiner
record, and never mints an outcome itself. A producer that ran the executor and then
counted its own passes would be the defendant writing the verdict.

    python3 drive.py                 # writes execution_run.json beside produce.py
    python3 drive.py --out PATH      # elsewhere

Every variant is driven TWICE, on purpose. The control run is the same variant on
`no_mediation`, where nothing sits between client and upstream, so it proves the hostile
stimulus actually reaches the client. A `proxy_strict` outcome with no such proof is not a
measurement, because "the stand in held" is also what an unplayed scenario looks like.

What this will not do: call a model, open a network connection, spend, or retry. A variant
that refuses or errors is recorded once. Three silent retries turn a flaky harness green.

Exit 0 when every drivable variant has a record, 3 for a refusal (corpus unreadable,
nothing drivable, lock not taken), as `produce.py` uses 3. Never 1 for a state this
file was designed for.

WIRE NAMES. `Run.client_wire` is what the adapter wrote INTO the mediator (the requests).
`Run.upstream_wire` is what came back OUT toward the client. The record uses the names
`bytes_into_mediator` and `bytes_to_client` so the direction cannot be read the wrong way
round. The first prototype read it wrongly and its control reported "payload not
delivered", which is the control doing its job.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / ".." / "boundary"))

import schema                                              # noqa: E402

RECORD_SCHEMA = schema.EXEC_RECORD_SCHEMA
RUN_SCHEMA = schema.EXEC_RUN_SCHEMA
ROUTE = "proxy_strict"
CONTROL_ROUTE = "no_mediation"
MODE = "head_of_line"
KIND = "harness_stand_in"          # E7: never relabelled as a product route
PRIVATE_TMP = pathlib.Path("/private/tmp")
OUT_PATH = HERE / "execution_run.json"
SESSION_TIMEOUT_MS = 20000

# The ledger counts CHARGED driver invocations. Nothing in this file can make one: it has
# no model client and no network call, and a test reads this source to keep it that way.
# The nightly line "this nightly, 0 live calls" is built from this header field.
LIVE_CALLS = 0
LEDGER_SCOPE = "no_live_calls_standin_run"

# The lock is a convention of whoever runs the loop (several seats share one machine), so
# its location comes from the environment and is not hardcoded to anyone's home.
LOCK_ENV = "GAUNTLET_HEAVY_LOCK"
LOCK_POLL_SECONDS = 5
LOCK_WAIT_SECONDS = 1800


class Refusal(Exception):
    """The loop is not allowed to run. Exit 3, designed for, not a crash."""


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="seconds")


def _git_head(repo: pathlib.Path) -> str | None:
    try:
        out = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True,
                             text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    sha = out.stdout.strip()
    return sha if out.returncode == 0 and len(sha) == 40 else None


# What moves between two runs of the SAME variant on the SAME code, found by running each
# one 25 times: clocks (at, mono, elapsed_ms, waited_ms), process and run identity (pid,
# run_id), the run root inside argv, and the child's own stdout and stderr text. None of
# these is a fact about the scenario, and all of them change every hash.
VOLATILE_KEYS = frozenset({"at", "mono", "run_id", "pid", "elapsed_ms", "waited_ms", "stdout",
                           "stderr", "stdout_bytes", "upstream_argv", "scanner_argv",
                           "upstream_argv_sha256", "scanner_argv_sha256"})


def normalise(value):
    """The value with every volatile key removed, JSON text inside strings (receipt `raw`) too."""
    if isinstance(value, dict):
        return {k: normalise(v) for k, v in value.items() if k not in VOLATILE_KEYS}
    if isinstance(value, list):
        return [normalise(v) for v in value]
    if isinstance(value, str) and value[:1] in "{[":
        try:
            return json.dumps(normalise(json.loads(value)), sort_keys=True)
        except ValueError:
            return value
    return value


def stable_digest_of(blob: bytes, jsonl: bool, root: pathlib.Path | None = None) -> str | None:
    """sha256 over the normalised content, canonical JSON, so two runs of one variant compare equal.

    `root` is the run directory. The adapter writes it INTO requests (the drop path of a file
    effect), so it is replaced by a fixed token before parsing."""
    if root is not None:
        blob = blob.replace(str(root).encode(), b"<RUN_ROOT>")
    try:
        items = [json.loads(l) for l in blob.splitlines() if l.strip()] if jsonl else json.loads(blob)
    except ValueError:
        return None
    return hashlib.sha256(json.dumps(normalise(items), sort_keys=True).encode()).hexdigest()


def _stable_file(path: pathlib.Path, jsonl: bool, root: pathlib.Path | None = None) -> str | None:
    try:
        return stable_digest_of(path.read_bytes(), jsonl, root)
    except OSError:
        return None


def _sha(path: pathlib.Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def payload_in(wire: bytes, payload: bytes) -> bool | None:
    """Is the stimulus in these bytes, raw or as a JSON string body. None when there is no payload."""
    if not payload:
        return None
    text = payload.decode("utf-8", "replace")
    needles = {payload, json.dumps(text)[1:-1].encode(), json.dumps(text, ensure_ascii=False)[1:-1].encode()}
    return any(n and n in wire for n in needles)


def classify_run(run, control_delivered: bool | None, expect_absent: bool | None = None,
                 payload_in_strict: bool | None = None, expect_original: bool | None = None,
                 original_delivered: bool | None = None,
                 origin: str | None = None) -> tuple[str, str | None, dict]:
    """(outcome, reason_code, evidence) for one proxy_strict run that returned.

    The four things a green can hide, each one a refusal and never a pass:
      the control did not deliver the stimulus   -> the stimulus is unproven
      no assertion had a subject                 -> nothing was observed to hold
      a harness stall fired                      -> the harness gave up, not the product
      the upstream spoke frames the seed does not declare (raised by execute.run, handled by the caller)
    `failed` is only ever a property that was OBSERVED not to hold.
    """
    held_true = [a["op"] for a in run.assertions if a.get("held") is True]
    held_false = [a["op"] for a in run.assertions if a.get("held") is False]
    no_subject = [a["op"] for a in run.assertions if a.get("held") is None]
    stalled = any(a.get("op") == "harness_stall" for a in run.assertions)
    evidence = {"held": held_true, "not_held": held_false, "no_subject": no_subject,
                "expect_payload_absent": expect_absent, "payload_at_destination": payload_in_strict,
                "stimulus_origin": origin, "expect_original": expect_original,
                "declared_frames_delivered_unchanged": original_delivered}
    if stalled:
        return "refused", "EXEC_OBSERVER_ABSENT", evidence
    if control_delivered is not True:
        return "refused", "EXEC_OBSERVER_ABSENT", evidence
    # THE FROZEN EXPECTATION, observed from the bytes. A schedule with no assert step has no
    # subject of its own, and "no assertion failed" would then read as "held". The seed says
    # what must NOT reach the client.
    if held_false or (expect_absent is True and payload_in_strict is True) or (
            expect_original is True and original_delivered is False):
        return "failed", "EXEC_CONTRADICTED", evidence
    if expect_absent is True and payload_in_strict is False:
        held_true = held_true + [f"payload_absent_at_destination({origin})"]
        evidence["held"] = held_true
    if expect_original is True and original_delivered is True:
        held_true = held_true + ["declared_frames_delivered_unchanged"]
        evidence["held"] = held_true
    if not held_true:
        return "refused", "EXEC_OBSERVER_ABSENT", evidence
    return "passed", None, evidence


def _declared(run_root: pathlib.Path) -> list:
    """The frames the schedule has the upstream send, parsed, from the run's own declared file."""
    f = run_root / "upstream.declared.jsonl"
    out = []
    if f.is_file():
        for line in f.read_bytes().splitlines():
            if line.strip():
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def stable_record_digest(record: dict) -> str:
    """The determinism key: the record without its timestamps and its volatile evidence block."""
    core = {k: v for k, v in record.items() if k not in ("started_at", "finished_at", "seconds",
                                                         "volatile", "stable_record_digest")}
    return hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()


def _finish(record: dict) -> dict:
    record["finished_at"] = _now()
    record["stable_record_digest"] = stable_record_digest(record)
    return record


def drive_one(variant_id: str, repo: pathlib.Path = REPO, run_parent: pathlib.Path = PRIVATE_TMP) -> dict:
    """One variant, one record. Never raises for a state it was designed for."""
    scenario_id, _, variant_name = variant_id.partition(".")
    record = {
        "record_schema": RECORD_SCHEMA, "variant_id": variant_id, "scenario_id": scenario_id,
        "variant": variant_name, "route": ROUTE, "implementation_kind": KIND, "mode": MODE,
        "control_route": CONTROL_ROUTE, "started_at": _now(), "harness_head": _git_head(repo),
        "outcome": None, "reason_code": None,
    }
    sys.path.insert(0, str(repo / "gauntlet" / "boundary"))
    try:
        import runner                                       # noqa: E402
        from gen2 import artifacts, execute                 # noqa: E402
    except Exception as exc:                                # noqa: BLE001
        record.update(outcome="errored", reason_code="RUN_FAILED",
                      cause=f"{type(exc).__name__}: {str(exc)[:200]}")
        return _finish(record)

    try:
        entry = next(e for e in runner.load_manifest()["scenarios"] if e["id"] == scenario_id)
        variant = next(v for v in runner.scenario_of(entry)["variants"] if v["name"] == variant_name)
    except (StopIteration, OSError, KeyError) as exc:
        record.update(outcome="errored", reason_code="RUN_FAILED",
                      cause=f"variant id does not resolve: {type(exc).__name__}: {str(exc)[:160]}")
        return _finish(record)

    # THE DELIVERY, verified against its own record, BEFORE a run directory exists.
    try:
        delivered = artifacts.of_record(entry, variant)
    except (artifacts.ArtifactsNotAsDelivered, OSError) as exc:
        record.update(outcome="refused", reason_code="EVIDENCE_UNBOUND",
                      cause=f"{type(exc).__name__}: {str(exc)[:240]}")
        return _finish(record)
    record["delivered_digest"] = delivered.digest

    roots = {r: run_parent / f"drv-{uuid.uuid4().hex[:10]}-{r}" for r in (CONTROL_ROUTE, ROUTE)}
    try:
        # CONTROL FIRST. Nothing mediates, so the client wire is the upstream's and the hostile
        # terminal arrives unchanged. If it does not, the stimulus never applied.
        control_delivered = None
        ctl_sent = ctl_visible = ctl_frames = None
        try:
            control = execute.run(entry, variant, route=CONTROL_ROUTE, run_root=roots[CONTROL_ROUTE])
            ctl_declared = _declared(roots[CONTROL_ROUTE])
            ctl_back = execute._messages(control.upstream_wire)
            ctl_sent = payload_in(control.client_wire, delivered.payload)
            ctl_visible = payload_in(control.upstream_wire, delivered.payload)
            ctl_frames = bool(ctl_declared) and all(f in ctl_back for f in ctl_declared)
            # Proof the stimulus APPLIED, by where it starts. A client side stimulus is proven by
            # the send. An upstream side one by the declared frames arriving at the client with
            # no mediator in the way.
            control_delivered = bool(control.upstream_as_declared) and (ctl_sent is True or ctl_frames)
            record["control"] = {
                "route": CONTROL_ROUTE, "stimulus_delivered": control_delivered,
                "payload_sent_by_client": ctl_sent, "payload_visible_at_client": ctl_visible,
                "declared_frames_reached_client": ctl_frames,
                "terminal_arrived": control.terminal is not None,
                "client_bound_wire_stable_sha256": stable_digest_of(control.upstream_wire, True,
                                                                    roots[CONTROL_ROUTE]),
                "execution_stable_sha256": _stable_file(roots[CONTROL_ROUTE] / "execution.json", False,
                                                        roots[CONTROL_ROUTE])}
        except (execute.TerminalNeverArrived, execute.UpstreamNotAsDeclared, execute.DeclaredFileMissing,
                execute.UnsupportedRoute) as exc:
            record["control"] = {"route": CONTROL_ROUTE, "stimulus_delivered": False,
                                 "refusal": f"{type(exc).__name__}: {str(exc)[:200]}"}

        try:
            run = execute.run(entry, variant, route=ROUTE, run_root=roots[ROUTE], mode=MODE,
                              engine_root=repo, timeout_ms=SESSION_TIMEOUT_MS)
        except (execute.TerminalNeverArrived, execute.UpstreamNotAsDeclared, execute.DeclaredFileMissing,
                execute.UnsupportedRoute) as exc:
            record.update(outcome="refused", reason_code="EXEC_OBSERVER_ABSENT",
                          cause=f"{type(exc).__name__}: {str(exc)[:240]}")
            return _finish(record)
        except Exception as exc:                            # noqa: BLE001
            record.update(outcome="errored", reason_code="RUN_FAILED",
                          cause=f"{type(exc).__name__}: {str(exc)[:240]}")
            return _finish(record)

        exp_path = runner.PACKAGE / entry["directory"] / variant.get("expected", "expected.json")
        try:
            exp = json.loads(exp_path.read_text())["variants"][variant["name"]][ROUTE]
            expect_absent = (exp.get("bytes_delivered") or {}).get("assert_original_payload_absent")
            record["expectation"] = {"source_sha256": _sha(exp_path),
                                     "policy_decision": (exp.get("policy") or {}).get("decision"),
                                     "assert_original_payload_absent": expect_absent}
        except (OSError, KeyError, ValueError):
            expect_absent = None
            exp = {}
            record["expectation"] = {"source_sha256": _sha(exp_path), "unreadable": True}
        origin = "client" if payload_in(run.client_wire, delivered.payload) else "upstream"
        if origin == "client":
            egress = execute._forwarded_upstream(roots[ROUTE] / "proxy.receipts.jsonl")
            dest_has = payload_in(b"\n".join(json.dumps(m).encode() for m in egress), delivered.payload)
        else:
            dest_has = payload_in(run.upstream_wire, delivered.payload)   # upstream_wire = what reached the client
        expect_original = ((exp.get("bytes_delivered") or {}).get("outcome") == "original"
                           if isinstance(exp, dict) else None)
        declared = _declared(roots[ROUTE])
        original_delivered = (all(f in execute._messages(run.upstream_wire) for f in declared)
                              if declared and expect_original else None)
        if isinstance(record.get("expectation"), dict):
            record["expectation"]["bytes_outcome"] = (exp.get("bytes_delivered") or {}).get("outcome")
        # ABSENCE MEANS NOTHING UNLESS PRESENCE WAS SHOWN. "The payload is not at the destination"
        # is also true of a variant whose stimulus is a size or a shape and not these bytes, so
        # the control must have SEEN the payload on the same side with nothing mediating.
        if expect_absent is True:
            control_delivered = bool(control_delivered) and (
                ctl_sent is True if origin == "client" else ctl_visible is True)
            record["control"]["stimulus_delivered"] = control_delivered
        outcome, reason, evidence = classify_run(run, control_delivered, expect_absent, dest_has,
                                                 expect_original, original_delivered, origin)
        record.update(
            outcome=outcome, reason_code=reason, assertions=evidence,
            graded_on=(["schedule_assertions"] if run.assertions else [])
            + ([f"payload_absent_at_destination({origin})"] if expect_absent is True else [])
            + (["declared_frames_delivered_unchanged"] if expect_original and declared else []),
            steps=[s["op"] for s in run.steps], primary_id=run.primary_id,
            terminal_expected=run.terminal_expected, terminal_arrived=run.terminal is not None,
            upstream_as_declared=run.upstream_as_declared, mediator_disposition=run.disposition,
            client_bound_wire_stable_sha256=stable_digest_of(run.upstream_wire, True, roots[ROUTE]),
            into_mediator_wire_stable_sha256=stable_digest_of(run.client_wire, True, roots[ROUTE]),
            execution_stable_sha256=_stable_file(roots[ROUTE] / "execution.json", False, roots[ROUTE]),
            receipts_stable_sha256=_stable_file(roots[ROUTE] / "proxy.receipts.jsonl", True, roots[ROUTE]),
            volatile={"bytes_to_client": len(run.upstream_wire), "bytes_into_mediator": len(run.client_wire),
                      "execution_sha256": _sha(roots[ROUTE] / "execution.json"),
                      "receipts_sha256": _sha(roots[ROUTE] / "proxy.receipts.jsonl")})
        return _finish(record)
    finally:
        for root in roots.values():
            shutil.rmtree(root, ignore_errors=True)


def records_digest(records: list[dict]) -> str:
    """One definition, shared with the validator that recomputes it."""
    return schema.records_digest(records)


def counts_of(records: list[dict]) -> dict:
    counts = {"passed": 0, "failed": 0, "refused": 0, "errored": 0}
    for record in records:
        if record.get("outcome") in counts:
            counts[record["outcome"]] += 1
    return counts


def build_run_doc(records: list[dict], *, started_at: str, corpus_digest: str | None,
                  repo: pathlib.Path = REPO, run_id: str | None = None) -> dict:
    """The run document: a header and the records, with the digest that binds them."""
    import produce                                          # noqa: E402  (digest helpers only)
    head = _git_head(repo)
    return {
        "header": {
            "schema": RUN_SCHEMA, "run_id": run_id or uuid.uuid4().hex[:16],
            "started_at": started_at, "finished_at": _now(),
            "harness_head": head, "engine_head": _git_head(repo),
            "corpus_digest": corpus_digest,
            "adapter_digest": produce._digest_file(pathlib.Path(produce.adapter.__file__)),
            "execute_digest": produce._digest_file(repo / "gauntlet" / "boundary" / "gen2" / "execute.py"),
            "driver_digest": produce._digest_file(pathlib.Path(__file__)),
            "route": ROUTE, "implementation_kind": KIND, "mode": MODE,
            "counts": counts_of(records),
            "records_digest": records_digest(records),
            "ledger": {"scope": LEDGER_SCOPE, "unit": schema.LEDGER_UNIT, "charges": LIVE_CALLS},
        },
        "records": sorted(records, key=lambda r: r["variant_id"]),
    }


def write_atomic(path: pathlib.Path, doc: dict) -> None:
    """Temp file in the same directory, fsync, rename. A crash leaves no partial document,
    so the producer sees the file absent and reports `not_run`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(json.dumps(doc, indent=1, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class Lock:
    """`mkdir` lock with an `owner` file. Polled, NEVER forced: a lock held by someone else is
    theirs, and breaking it is how two heavy runs end up on one machine."""

    def __init__(self, path: pathlib.Path | None, *, wait_seconds: float = LOCK_WAIT_SECONDS,
                 poll_seconds: float = LOCK_POLL_SECONDS, owner: str = "gauntlet drive.py"):
        self.path, self.wait, self.poll, self.owner, self.held = path, wait_seconds, poll_seconds, owner, False

    def __enter__(self):
        if self.path is None:
            return self
        deadline = time.monotonic() + self.wait
        while True:
            try:
                self.path.mkdir()
                break
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise Refusal(f"the heavy run lock is held by someone else and did not free "
                                  f"within {self.wait} seconds") from None
                time.sleep(self.poll)
        self.held = True
        (self.path / "owner").write_text(f"{self.owner} pid {os.getpid()} at {_now()}\n")
        return self

    def __exit__(self, *exc):
        if self.held:
            shutil.rmtree(self.path, ignore_errors=True)
            self.held = False
        return False


def drive_all(out: pathlib.Path = OUT_PATH, repo: pathlib.Path = REPO) -> int:
    import produce                                          # noqa: E402  (the same planner, so 29 is the producer's 29)
    started = _now()
    corpus_digest = produce._digest_tree(produce.MATERIALISED)
    if corpus_digest is None:
        raise Refusal("the pinned corpus is not present or cannot be listed on this host")
    planned = produce.plan_corpus()
    if not planned["drivable"]:
        raise Refusal("the planner found nothing drivable")
    lock_path = os.environ.get(LOCK_ENV)
    with Lock(pathlib.Path(lock_path) if lock_path else None, wait_seconds=LOCK_WAIT_SECONDS):
        records = [drive_one(variant_id, repo) for variant_id in sorted(planned["drivable"])]
    write_atomic(out, build_run_doc(records, started_at=started, corpus_digest=corpus_digest, repo=repo))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=str(OUT_PATH))
    ns = ap.parse_args(argv)
    try:
        code = drive_all(pathlib.Path(ns.out))
    except Refusal as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    print(f"wrote {ns.out}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
