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
import pathlib
import sys
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "boundary"))

import schema                                              # noqa: E402
import classify                                            # noqa: E402
from gen2 import adapter, loader                           # noqa: E402

REPORT_DIR = pathlib.Path(__file__).resolve().parents[1] / "boundary" / "evidence"
REPORT_PATH = REPORT_DIR / "nightly.json"

# Imported records. Each is authored OUTSIDE this process and simply absent
# today. Absent is a state the page renders, not a number it invents.
EXAMINER_RECORD = pathlib.Path(__file__).with_name("examiner_record.json")
LEDGER_RECORD = pathlib.Path(__file__).with_name("ledger_record.json")

MATERIALISED = (pathlib.Path.home() / "Desktop" / "SUNGLASSES_ASTRA_REVIEW_2026-09-04"
                / "GATE3_DESIGN_REVIEW_2026-09-13" / "materialized")


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _digest_file(path: pathlib.Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _digest_tree(root: pathlib.Path) -> str | None:
    """One digest over the corpus, so a changed variant changes the identity.

    Names as well as bytes: a renamed file is a different corpus, and hashing
    only contents would call the two the same.
    """
    if not root.is_dir():
        return None
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        h.update(str(path.relative_to(root)).encode())
        h.update(hashlib.sha256(path.read_bytes()).digest())
    return h.hexdigest()


def _unavailable(reason_code: str, detail: str) -> dict:
    """A panel with no number in it at all.

    Deliberately carries no numeric keys. A panel that kept a stale integer
    beside its state invites exactly the transcription a renderer bug would
    then publish.
    """
    return {"state": "unavailable", "reason_code": reason_code, "detail": detail}


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
    if not materialised.is_dir():
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


def coverage_panel(planned: dict, capmap: dict) -> dict:
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
        # E2: execution is a separate partition and never inherits planning.
        "execution_partition": {
            "passed": 0, "failed": 0, "refused": 0, "errored": 0,
            "not_run": total,
        },
        "execution_state": "not_run",
        "execution_reason_code": "EXEC_NOT_RUN",
    }

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
        unresolved = dict(classification.unknown)
        unresolved.update(classification.uncovered)
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

    if capmap is None:
        coverage = _unavailable("EVIDENCE_UNBOUND",
                                f"capability map unusable: {capmap_error}")
    elif corpus_digest is None:
        coverage = _unavailable("EVIDENCE_UNBOUND",
                                "the pinned corpus is not present on this host")
    else:
        coverage = coverage_panel(planned, capmap)

    examiner, examiner_digest = _load_optional(EXAMINER_RECORD)
    ledger, ledger_digest = _load_optional(LEDGER_RECORD)

    # E1. FIT is imported or it is absent. It is never minted here.
    if examiner is None:
        harness = _unavailable(
            "EVIDENCE_UNBOUND",
            "no examiner-authored machine-readable record. FIT is a finding "
            "about the instrument made by the examiner on a dated head under a "
            "named contract; this run may reference such a record and may not "
            "write one. The delivered mutation plan holds 73 entries over 7 "
            "requirements and is not the 119-mutation examination manifest, so "
            "it cannot stand in for one.")
    else:
        harness = {"state": "historical", "record": examiner,
                   "record_digest": examiner_digest}

    # E9. Scope or nothing. The one delivered ledger counts 34 charges for a
    # single run; publishing it under the cumulative cap's label would be a
    # scope error wearing a citation.
    if ledger is None:
        ledger_panel = _unavailable(
            "EVIDENCE_UNBOUND",
            "no ledger record declaring its own scope, cap, updated_at and "
            "digest. Budget policy is T9's; this process does not author it.")
    else:
        ledger_panel = {"state": "measured", "unit": schema.LEDGER_UNIT,
                        "record": ledger, "record_digest": ledger_digest}

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
            "rows": {"state": "unavailable",
                     "reason_code": "EVIDENCE_UNBOUND",
                     "detail": "no row results are bound to an executed head. "
                               "Stand-in planning counts are not route "
                               "conformance and are never relabelled as such."},
        }],
        "ledger": ledger_panel,
    }

    # The terminal state, decided last and from the report itself.
    refusing = (
        coverage.get("state") == "unavailable"
        or coverage.get("ceiling", {}).get("state") == "not_computed"
    )
    if refusing:
        report["run"]["outcome"] = "refused"
        report["run"]["exit_code"] = 3
        report["run"]["reason_code"] = "RUN_REFUSED"
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
