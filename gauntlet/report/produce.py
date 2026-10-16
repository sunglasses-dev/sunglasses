"""Write tonight's report, including the report that says tonight proved little.

E5 is the rule that shapes this file: a run that refuses or fails still writes a
schema-valid TERMINAL report, and still exits nonzero. The two are not in
tension. If a failing run wrote nothing, the page-build gate would have nothing
to publish, yesterday's green would stay up, and a broken harness would look
exactly like a passing one from outside. So the supervisor always emits; the
publisher decides separately what to commit; the job's own outcome stays honest.

What this producer may NOT do, in the words of the design verdict:

  It may not mint FIT from its own green suite. FIT is an EXAMINER's finding
  about the instrument, on a dated head, under a named contract. A nightly run
  asserting it from a passing local suite is the defendant writing the verdict.

  It may not publish a count whose denominator it cannot bind. Two traps were
  found while writing this: the delivered mutation plan holds 73 entries over 7
  requirements, which is NOT the 119 semantic mutations of the examination, and
  the delivered ledger record counts 34 charges for ONE run, which is not the
  36 of the cumulative authorised scope. Either number, rendered under the other
  one's label, would have been a lie with a citation attached. Both panels are
  therefore `unavailable` until a record that declares its own scope exists.

So: coverage is measured here, because this process plans it against pinned
artifacts and can show its work. Everything else is imported or it is absent,
and absent renders as `unavailable`, never as zero.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "boundary"))

import review_root                                         # noqa: E402
import schema                                              # noqa: E402
import classify                                            # noqa: E402
from gen2 import adapter, loader                           # noqa: E402

REPORT_DIR = pathlib.Path(__file__).resolve().parents[1] / "boundary" / "evidence"
REPORT_PATH = REPORT_DIR / "nightly.json"

# Imported records. Each is authored OUTSIDE this process and simply absent
# today. Absent is a state the page renders, not a number it invents.
EXAMINER_RECORD = pathlib.Path(__file__).with_name("examiner_record.json")
LEDGER_RECORD = pathlib.Path(__file__).with_name("ledger_record.json")
# Written by drive.py, never by this file. Absent means nothing was executed.
EXECUTION_RUN = pathlib.Path(__file__).with_name("execution_run.json")

# GAUNTLET_REVIEW_ROOT, read in ONE place (review_root.py); unset = absent = refusal.
MATERIALISED = review_root.GATE3 / "materialized"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _digest_file(path: pathlib.Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


ENGINE_HEAD_ENV = "GAUNTLET_ENGINE_HEAD"


def engine_head() -> str | None:
    """The engine commit this report is built against, resolved here and not read from the run.

    A run document names the engine it ran on, and a document cannot vouch for itself. The pin is
    the environment value a nightly sets from the archive it exported, else the head of the
    checkout this file sits in. Anything that is not a full 40 character commit is no pin at all,
    and a run is never bound to no pin.
    """
    pinned = (os.environ.get(ENGINE_HEAD_ENV) or "").strip().lower()
    if not pinned:
        try:
            out = subprocess.run(["git", "-C", str(pathlib.Path(__file__).resolve().parents[2]),
                                  "rev-parse", "HEAD"], capture_output=True, text=True, timeout=20)
            pinned = out.stdout.strip().lower() if out.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            pinned = ""
    return pinned if len(pinned) == 40 and all(c in "0123456789abcdef" for c in pinned) else None


def _corpus_access(root: pathlib.Path) -> tuple[bool, str | None]:
    """(listable, why_not). Absent is (False, None). Present but not listable is
    (False, <the OS error class and text, no path>).

    An unreadable review folder (a macOS privacy block, a mode 000 directory)
    must end in the same refusal as an absent one, never in a traceback. The
    reason is kept so the refusal can say which of the two it is, and the path is
    left out because this text can reach a published artifact.
    """
    try:
        if not root.is_dir():
            return False, None
        with os.scandir(root):
            return True, None
    except OSError as exc:
        return False, f"{type(exc).__name__}, {exc.strerror or 'no OS text'}, errno {exc.errno}"


def _digest_tree(root: pathlib.Path) -> str | None:
    """One digest over the corpus, so a changed variant changes the identity.

    Names as well as bytes: a renamed file is a different corpus, and hashing
    only contents would call the two the same.
    """
    if not _corpus_access(root)[0]:
        return None
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        h.update(str(path.relative_to(root)).encode())
        h.update(hashlib.sha256(path.read_bytes()).digest())
    return h.hexdigest()


def _unavailable(reason_code: str) -> dict:
    """A panel with no number in it at all.

    Deliberately carries no numeric keys. A panel that kept a stale integer
    beside its state invites exactly the transcription a renderer bug would
    then publish. It carries no sentence either: the page prints the fixed text for the reason
    code, and a free form string has nothing in the report to bind it.
    """
    return {"state": "unavailable", "reason_code": reason_code}


def _load_optional(path: pathlib.Path) -> tuple[dict | None, str | None]:
    if not path.is_file():
        return None, None
    try:
        return json.loads(path.read_text()), _digest_file(path)
    except ValueError:
        return None, _digest_file(path)


def _schedule_of(directory: pathlib.Path) -> dict | None:
    for candidate in sorted(directory.glob("*.json")):
        try:
            data = json.loads(candidate.read_text())
        except ValueError:
            continue
        if isinstance(data, dict) and "profile_steps" in data:
            return data
    return None


def plan_corpus(materialised: pathlib.Path = MATERIALISED) -> dict:
    """Plan every variant, and keep the three memberships apart.

    drivable / blocked / invalid is a PLANNING partition. It says nothing about
    execution: a drivable variant that never ran is `not_run`, never `passed`.
    """
    result = {"drivable": [], "blocked": {}, "invalid": {}}
    if not _corpus_access(materialised)[0]:
        return result
    for directory in sorted(p for p in materialised.iterdir() if p.is_dir()):
        variant_id = directory.name
        sched = _schedule_of(directory)
        if sched is None:
            result["invalid"][variant_id] = {
                "reason_code": "PLAN_INVALID_SCHEDULE",
                "detail": "no schedule document in the delivered directory"}
            continue
        steps = list(sched.get("profile_steps") or [])
        try:
            adapter.plan(sched)
        except (adapter.UnimplementedOperation, adapter.UnsupportedEvent):
            result["blocked"][variant_id] = steps
        except (adapter.StepContractViolation, adapter.NoStepsToDrive) as exc:
            result["invalid"][variant_id] = {
                "reason_code": "PLAN_INVALID_SCHEDULE", "detail": str(exc)[:200]}
        except Exception as exc:                    # noqa: BLE001
            # E4: a planner that throws unexpectedly is an ERROR, never a
            # capability blocker. Calling it "needs route capability" would
            # convert our own defect into a statement about the product.
            result["invalid"][variant_id] = {
                "reason_code": "PLAN_PLANNER_ERROR",
                "detail": f"{type(exc).__name__}: {str(exc)[:160]}"}
        else:
            result["drivable"].append(variant_id)
    return result


def _parse_time(value) -> datetime.datetime | None:
    try:
        parsed = datetime.datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.timezone.utc)


def usable_run(run_doc, corpus_digest: str | None, started: str) -> tuple[dict | None, str | None]:
    """The run document if this report may count it, else (None, why not).

    A run document is the driver's claim about an earlier moment, so it is checked against
    TONIGHT's identities before one record in it is counted: the same corpus, the same adapter
    code, a known schema, and young enough for the freshness policy. A document that fails any
    of these is not zero executed and not a pass, it is evidence this report cannot bind.
    """
    if run_doc is None:
        return None, None
    header = run_doc.get("header") if isinstance(run_doc, dict) else None
    records = run_doc.get("records") if isinstance(run_doc, dict) else None
    if not isinstance(header, dict) or not isinstance(records, list):
        return None, "the execution run document is not a header and a list of records"
    problem = malformed_record(records)
    if problem:
        return None, problem
    if header.get("schema") != schema.EXEC_RUN_SCHEMA:
        return None, f"the execution run schema {header.get('schema')!r} is not known"
    if header.get("corpus_digest") != corpus_digest:
        return None, "the execution run was made against a different corpus than this report"
    if header.get("adapter_digest") != _digest_file(pathlib.Path(adapter.__file__)):
        return None, "the execution run was made with different adapter code than this report"
    pin = engine_head()
    if pin is None or header.get("engine_head") != pin:
        return None, ("the execution run was made on a different engine commit than the one this "
                      "report is pinned to, or no engine commit is pinned")
    finished, measured = _parse_time(header.get("finished_at")), _parse_time(started)
    if (finished is None or measured is None or
            measured - finished > datetime.timedelta(hours=schema.DEFAULT_FRESHNESS_HOURS)):
        return None, ("the execution run is older than the freshness policy, or undated")
    if finished > measured or finished > datetime.datetime.now(datetime.timezone.utc):
        return None, "the execution run finished after the measurement that would carry it"
    return run_doc, None


def malformed_record(records) -> str | None:
    """Why a list of records cannot be counted, or None. A record is shaped as `schema` says,
    every nested field included. One that is not makes the whole document unreadable, because a
    count that skips what it cannot read is a count of a different document."""
    for index, record in enumerate(records):
        problem = schema.record_shape_problem(record)
        if problem:
            return f"record {index} of the execution run cannot be read: {problem}"
    return None


def execution_partition(planned: dict, run_doc: dict | None) -> tuple[dict, str, str | None]:
    """(partition, state, reason_code), counted from the driver's records and nothing else.

    No run document is exactly the panel this file always produced. A record for a variant that
    is not drivable tonight is NOT counted here (the validator turns it into a finding), so a
    stale or edited run file cannot inflate a partition. Variants the planner cannot drive stay
    `not_run`, as does a drivable variant with no record.
    """
    total = len(planned["drivable"]) + len(planned["blocked"]) + len(planned["invalid"])
    if run_doc is None:
        return ({"passed": 0, "failed": 0, "refused": 0, "errored": 0, "not_run": total},
                "not_run", "EXEC_NOT_RUN")
    drivable = set(planned["drivable"])
    seen, counts = set(), {"passed": 0, "failed": 0, "refused": 0, "errored": 0}
    for record in run_doc["records"]:
        if not isinstance(record, dict) or not isinstance(record.get("variant_id"), str):
            continue                    # the validator and `usable_run` refuse these. Never count
        variant_id = record.get("variant_id")
        if (variant_id in drivable and variant_id not in seen
                and isinstance(record.get("outcome"), str) and record.get("outcome") in counts):
            seen.add(variant_id)
            counts[record["outcome"]] += 1
    part = dict(counts)
    part["not_run"] = total - sum(counts.values())
    return part, "measured", None


def coverage_panel(planned: dict, capmap: dict, run_doc: dict | None = None) -> dict:
    """Planning counts, and the ceiling only if it is genuinely computable."""
    drivable, blocked, invalid = planned["drivable"], planned["blocked"], planned["invalid"]
    total = len(drivable) + len(blocked) + len(invalid)

    panel = {
        "state": "measured",
        "unit": "corpus variants",
        "plan_partition": {
            "drivable": len(drivable),
            "blocked": len(blocked),
            "invalid": len(invalid),
        },
        "total": total,
        "drivable_ids": sorted(drivable),
        "blocked_ids": sorted(blocked),
        "invalid_detail": invalid,
    }
    # E2: execution is a separate partition and never inherits planning.
    (panel["execution_partition"], panel["execution_state"],
     panel["execution_reason_code"]) = execution_partition(planned, run_doc)

    # CLASSIFY EVERYTHING FIRST. No ceiling, no subtotal and no category count
    # exists before this returns, which is the whole fix for the short circuit.
    classification = classify.classify(blocked, capmap)

    if not blocked:
        panel["ceiling"] = {
            "state": "not_applicable",
            "reason_code": "CEILING_NO_BLOCKED_VARIANTS",
            "blocked_needing_route": None,
            "blocked_by_adapter_work_alone": None,
        }
        return panel

    if not classification.complete:
        # A code for each operation, never the map's sentence. The page prints the fixed text for
        # the code, and the sentence stays in the reviewed map where it can be read and checked.
        unresolved = {op: "CEILING_OP_OPEN_QUESTION" for op in classification.unknown}
        unresolved.update({op: "CEILING_OP_NOT_IN_MAP" for op in classification.uncovered})
        panel["ceiling"] = {
            "state": "not_computed",
            "reason_code": "CEILING_UNCLASSIFIED_OPS",
            "unclassified_count": len(unresolved),
            "unclassified": unresolved,
            # NULL, not zero. A refusal that emptied the lists would otherwise
            # publish two zeros that read as measurements of nothing blocking.
            "blocked_needing_route": None,
            "blocked_by_adapter_work_alone": None,
        }
        return panel

    needs_route, adapter_only = [], []
    for variant_id, steps in blocked.items():
        needs = classify.needs_of(variant_id, steps, capmap)
        if any(classification.buckets[n.tuple_key] == classify.ROUTE for n in needs):
            needs_route.append(variant_id)
        else:
            adapter_only.append(variant_id)

    ceiling = not adapter_only
    panel["ceiling"] = {
        "state": "true" if ceiling else "false",
        "reason_code": ("CEILING_ALL_BLOCKED_NEED_ROUTE" if ceiling
                        else "CEILING_ADAPTER_ONLY_MEMBER"),
        "blocked_needing_route": len(needs_route),
        "blocked_by_adapter_work_alone": len(adapter_only),
        "adapter_only_ids": sorted(adapter_only),
    }
    return panel


def ledger_panel_of(ledger: dict | None, ledger_digest: str | None, run_doc: dict | None) -> dict:
    """The ledger as two labelled lines, each built from a record and never typed.

    One line is the cumulative Gate 2 count from the imported ledger record. The other is this
    nightly run's own count from the driver's header. They are different scopes with different
    meanings, and a bare number under either label is the 34 versus 36 error the README says was
    nearly published. A line whose source is absent says so instead of leaving a gap, so the page
    cannot show one line and let the reader assume the other. Neither record exists: the panel is
    exactly what it was, unavailable.
    """
    if ledger is None and run_doc is None:
        # No ledger record declaring its own scope, cap, updated_at and digest. Budget policy is set
        # outside this process, which does not author it.
        return _unavailable("EVIDENCE_UNBOUND")

    lines = []
    if ledger is not None:
        lines.append({
            "scope": ledger.get("scope"), "cap": ledger.get("cap"),
            "charges": ledger.get("charges"), "unsettled": ledger.get("unsettled"),
            "updated_at": ledger.get("updated_at"), "source": "ledger_record",
            "record_digest": ledger_digest})
    else:
        lines.append({"scope": "cumulative_gate2", "state": "unavailable",
                      "reason_code": "EVIDENCE_UNBOUND", "source": "ledger_record"})
    if run_doc is not None:
        header = run_doc["header"]
        header_ledger = header.get("ledger") if isinstance(header.get("ledger"), dict) else {}
        lines.append({
            "scope": header_ledger.get("scope"),
            "charges": header_ledger.get("charges"),
            "updated_at": header.get("finished_at"), "source": "execution_run",
            "run_id": header.get("run_id"), "records_digest": header.get("records_digest")})
    else:
        lines.append({"scope": "no_live_calls_standin_run", "state": "unavailable",
                      "reason_code": "EVIDENCE_UNBOUND", "source": "execution_run"})
    for line in lines:
        line["text"] = schema.ledger_line_text(line) if "state" not in line else None

    panel = {"state": "measured", "unit": schema.LEDGER_UNIT, "lines": lines}
    if ledger is not None:
        panel["record"], panel["record_digest"] = ledger, ledger_digest
    return panel


def build(run_id: str | None = None) -> tuple[dict, int]:
    """The report and the exit code. Always both, even when it refuses."""
    started = _now()
    run_id = run_id or uuid.uuid4().hex[:16]

    capmap_error = None
    try:
        capmap = classify.load_map()
    except classify.MapInvalid as exc:
        capmap, capmap_error = None, str(exc)

    planned = plan_corpus()
    corpus_digest = _digest_tree(MATERIALISED)
    _, corpus_why_not = _corpus_access(MATERIALISED)
    if corpus_why_not is not None:
        # The panel carries a reason code and no sentence, so the why goes to the console, not the report.
        print("gauntlet report: the pinned corpus is present but cannot be listed from this seat "
              f"({corpus_why_not})", file=sys.stderr)

    # The driver's records, imported like the examiner's. A document that does not bind to
    # tonight's corpus, code and freshness window is set aside with its reason, never counted.
    run_file, _ = _load_optional(EXECUTION_RUN)
    run_doc, run_set_aside = usable_run(run_file, corpus_digest, started)
    if run_doc is not None and capmap is None:
        run_doc, run_set_aside = None, ("the capability map is unusable, so no coverage panel "
                                        "exists to bind the execution run to")
    # A run file that cannot be read as records is not a stale run, it is a broken instrument.
    # It refuses (exit 3) and still writes the report, rather than raising and writing nothing.
    run_unreadable = None
    if run_file is None and EXECUTION_RUN.is_file():
        run_unreadable = "the execution run file is not valid JSON"
    elif isinstance(run_file, dict) and isinstance(run_file.get("records"), list):
        run_unreadable = malformed_record(run_file["records"]) or (
            None if isinstance(run_file.get("header"), dict)
            else "the execution run document is not a header and a list of records")
    elif run_file is not None:
        run_unreadable = "the execution run document is not a header and a list of records"
    if run_unreadable:
        run_set_aside = run_unreadable

    if capmap is None:
        coverage = _unavailable("EVIDENCE_UNBOUND")          # the capability map is unusable
    elif corpus_digest is None:
        coverage = _unavailable("EVIDENCE_UNBOUND")          # the pinned corpus is not on this host, or cannot be listed
    else:
        coverage = coverage_panel(planned, capmap, run_doc)
        if run_set_aside:
            coverage["execution_state"] = "unavailable"
            coverage["execution_reason_code"] = "EVIDENCE_UNBOUND"
            coverage["execution_detail"] = run_set_aside

    examiner, examiner_digest = _load_optional(EXAMINER_RECORD)
    ledger, _ = _load_optional(LEDGER_RECORD)
    # The digest is over the PARSED record, so the validator can recompute it from the record
    # embedded in the report. A digest of file bytes cannot be checked from the report alone.
    ledger_digest = schema.canonical_digest(ledger) if isinstance(ledger, dict) else None
    if ledger is not None and not isinstance(ledger, dict):
        ledger = None

    # E1. FIT is imported or it is absent. It is never minted here.
    if examiner is None:
        # No record written by the examiner in a form this run can read. FIT is a finding about the
        # instrument made by the examiner on a dated head under a named contract. This run may
        # reference such a record and may not write one. The delivered mutation plan holds 73 entries
        # over 7 requirements and is not the 119 mutation examination manifest, so it cannot stand
        # in for one.
        harness = _unavailable("EVIDENCE_UNBOUND")
    else:
        harness = {"state": "historical", "record": examiner,
                   "record_digest": examiner_digest}

    # E9. Scope or nothing. The one delivered ledger counts 34 charges for a
    # single run; publishing it under the cumulative cap's label would be a
    # scope error wearing a citation.
    ledger_panel = ledger_panel_of(ledger, ledger_digest, run_doc)

    report = {
        "schema": schema.SCHEMA_VERSION,
        "run": {
            "id": run_id,
            "attempt": 1,
            "started_at": started,
            "finished_at": _now(),
            "outcome": "complete",
            "exit_code": 0,
        },
        "identities": {
            "corpus_digest": corpus_digest,
            "corpus_path_label": "GATE3 delivered materialisation, 74 variants",
            "adapter_source_digest": _digest_file(
                pathlib.Path(adapter.__file__)),
            "loader_source_digest": _digest_file(pathlib.Path(loader.__file__)),
            "capability_map_digest": _digest_file(classify.MAP_PATH),
            "capability_map_revision": (capmap or {}).get("revision"),
            "capability_map_review_state": (capmap or {}).get("review_state"),
            "producer_digest": _digest_file(pathlib.Path(__file__)),
            "engine_head": engine_head(),
        },
        "freshness": {
            "policy_hours": schema.DEFAULT_FRESHNESS_HOURS,
            "measured_at": started,
            "generated_at": _now(),
            "published_at": None,
            "note": "Generation, measurement and publication are different "
                    "times. Republishing an old measurement does not refresh it.",
        },
        "harness": harness,
        "coverage": coverage,
        # E7. The states exist now so merge day is a data change, not a redesign.
        "routes": [{
            "name": "proxy_strict",
            "implementation_kind": "harness_stand_in",
            "head": None,
            "head_state": "unavailable",
            "head_reachable_on_origin": "unknown",
            "reachability_checked_at": None,
            # No row results are bound to an executed head. Stand in planning counts are not route
            # conformance and are never relabelled as such.
            "rows": {"state": "unavailable", "reason_code": "EVIDENCE_UNBOUND"},
        }],
        "ledger": ledger_panel,
    }

    # The terminal state, decided last and from the report itself.
    if run_doc is not None:
        report["identities"]["execution_run_digest"] = schema.canonical_digest(run_doc)
        report["identities"]["execution_harness_head"] = run_doc["header"].get("harness_head")
        report["execution_run"] = run_doc
        # The route stays a stand in with unavailable rows. What ran, and the limit of what the
        # examiner's finding says about it, sit beside them as data and never inside them.
        report["routes"][0]["execution"] = {
            "state": "measured",
            "records_digest": run_doc["header"].get("records_digest"),
            "harness_head": run_doc["header"].get("harness_head"),
            "counts": (dict(run_doc["header"]["counts"])
                       if isinstance(run_doc["header"].get("counts"), dict) else {}),
            "fit_scope": schema.STANDIN_SCOPE_SENTENCE,
        }

    refusing = (
        coverage.get("state") == "unavailable"
        or coverage.get("ceiling", {}).get("state") == "not_computed"
        or bool(run_unreadable)
    )
    # V15. A run that executed nothing is not a result, whatever the ceiling says. Another refusal
    # takes precedence: it is the more basic one.
    exec_none = (not refusing and schema.nothing_executed(coverage))
    if refusing or exec_none:
        report["run"]["outcome"] = "refused"
        report["run"]["exit_code"] = 3
        report["run"]["reason_code"] = "EXEC_NONE" if exec_none else "RUN_REFUSED"
    report["run"]["finished_at"] = _now()
    return report, report["run"]["exit_code"]


def main() -> int:
    report, code = build()
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(f"wrote {REPORT_PATH} outcome={report['run']['outcome']} exit={code}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
