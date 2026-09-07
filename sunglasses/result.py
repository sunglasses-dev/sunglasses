"""One canonical result shape, and one function that produces it.

WHY THIS MODULE EXISTS (v0.5.6 repair, round 3).
------------------------------------------------
Three result shapes were in circulation: ``engine.ScanResult``, the scanner's
aggregate dicts (``scan_fast``, ``scan_email``), and the deep/dependency-warning
dicts from the media extractors. Five consumers -- the CLI, the MCP server, the
SARIF serializer, ``scan_email`` and ``scan_auto`` -- each recomputed the three
axes their own way, or did not compute them at all.

Two review rounds fixed the *surfaces a reviewer happened to sample*, and a third
round of the same defect turned up in the next five samples: an email aggregate
that reported ``is_clean: true`` while listing an untranscribed attachment, a deep
branch that returned a dict with no axes in it whatsoever, and a CLI line that
computed ``inspection_complete = bool(sources_found) and (aggregate_clean or
threat_found)`` -- in which *finding a threat manufactured the coverage claim*.

So this is a fix by subtraction. Every per-consumer axis computation is deleted
and replaced by one call to ``normalize()``. The point is not that this function
is clever; it is that after this commit there is exactly ONE place in the package
where "was it clean" is decided, so the class of defect cannot recur in a surface
nobody sampled.

THE INVARIANTS, in one place:

1. ``is_clean = (not threat_found) and inspection_complete``. Always recomputed
   from the other two, never read from the input. An incoming ``is_clean`` is
   treated as an untrusted hint, because every bug this module closes was an
   incoming ``is_clean`` that lied.
2. **An absent axis is not a clean one.** A dict that never mentions
   ``inspection_complete`` did not inspect anything as far as we can prove, so it
   normalizes to ``inspection_complete: False``. Silence is not a pass.
3. **A finding never establishes coverage.** ``inspection_complete`` is derived
   only from extraction completeness, truncation and warnings. Whether a pattern
   fired is orthogonal, and conflating the two is what produced
   ``inspection_complete: true`` sitting beside ``extraction_complete: false``.
4. **Deferred and undecodable content counts as NOT inspected.** A
   ``needs_deep_scan`` entry and a missing-decoder warning both mean bytes went
   unread; both force ``inspection_complete: False``.
5. The serializer's fields (``channel``, ``event_id``, ``latency_ms``,
   ``decision``, ``severity``, ``source``) are always present with honest
   defaults, so no consumer needs a shim object to satisfy ``to_sarif``.

Scope: this is an adapter at the boundary. No extractor, parser, walker or engine
behaviour changes -- ``normalize()`` reads what those produce and does not ask
them to produce anything new.
"""

from typing import Any, Optional

__all__ = ["normalize", "aggregate", "CANONICAL_KEYS", "NormalizedResult"]


CANONICAL_KEYS = (
    # the three axes
    "threat_found",
    "inspection_complete",
    "is_clean",
    # coverage detail
    "extraction_complete",
    "truncated",
    "warnings",
    # findings and provenance
    "findings",
    "decision",
    "severity",
    "source",
    "channel",
    "event_id",
    "latency_ms",
)

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


def _as_list(value) -> list:
    """Coerce a warnings field to a list without inventing or dropping entries."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple, set)):
        return [w for w in value if w]
    return [value]


def _worst_severity(findings: list) -> str:
    if not findings:
        return "none"
    best = "none"
    for f in findings:
        sev = (f or {}).get("severity", "none") if isinstance(f, dict) else "none"
        if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(best, 0):
            best = sev
    return best


def _findings_of(obj: Any) -> list:
    """Findings, wherever this particular shape happens to keep them.

    ``ScanResult`` uses ``findings``; the aggregates use ``threats``; the deep
    dicts nest per-source ``findings`` under ``results``. Reading all three here
    is the whole reason consumers no longer have to.
    """
    if not isinstance(obj, dict):
        return list(getattr(obj, "findings", None) or [])

    for key in ("findings", "threats"):
        value = obj.get(key)
        if value:
            return list(value)

    nested: list = []
    for sub in obj.get("results") or []:
        if isinstance(sub, dict):
            nested.extend(sub.get("findings") or [])
    if nested:
        return nested

    # Present-but-empty beats absent; either way the answer is an empty list.
    return []


def _normalize_scanresult(obj: Any, source: Optional[str]) -> dict:
    """A ``ScanResult`` already computes the axes correctly -- copy, don't redo."""
    findings = list(getattr(obj, "findings", None) or [])
    threat_found = bool(getattr(obj, "threat_found", bool(findings)))
    extraction_complete = bool(getattr(obj, "extraction_complete", True))
    truncated = bool(getattr(obj, "truncated", False))
    warnings = _as_list(getattr(obj, "extraction_warnings", None))
    inspection_complete = extraction_complete and not truncated

    return {
        "threat_found": threat_found,
        "inspection_complete": inspection_complete,
        "is_clean": (not threat_found) and inspection_complete,
        "extraction_complete": extraction_complete,
        "truncated": truncated,
        "warnings": warnings,
        "findings": findings,
        "decision": getattr(obj, "decision", "block" if threat_found else "allow"),
        "severity": getattr(obj, "severity", None) or _worst_severity(findings),
        "source": source if source is not None else getattr(obj, "source", None),
        "channel": getattr(obj, "channel", None) or "file",
        "event_id": getattr(obj, "event_id", None) or "",
        "latency_ms": getattr(obj, "latency_ms", None) or 0.0,
    }


def _normalize_mapping(obj: dict, source: Optional[str]) -> dict:
    """Any of the aggregate/deep/dependency-warning dicts.

    Every branch here is conservative on purpose: where the input is silent, the
    answer is "not inspected", never "clean".
    """
    findings = _findings_of(obj)
    threat_found = obj.get("threat_found")
    if threat_found is None:
        # Two other tells for the same fact, in order of directness.
        decision = obj.get("decision")
        threat_found = bool(findings) or (decision is not None and decision != "allow")
    threat_found = bool(threat_found)

    warnings = _as_list(obj.get("warnings"))
    # The dependency-warning dicts carry a singular `warning` and nothing else.
    # That string IS the statement that the file went unread, so it must both
    # survive into `warnings` and defeat completeness.
    single = obj.get("warning")
    if single and single not in warnings:
        warnings.append(single)

    truncated = bool(obj.get("truncated", False))

    # --- coverage, derived from evidence only; findings deliberately not consulted
    extraction_complete = obj.get("extraction_complete")
    if extraction_complete is None:
        if "inspection_complete" in obj:
            extraction_complete = bool(obj.get("inspection_complete"))
        else:
            # Invariant 2: silence is not a pass.
            #
            # v0.5.6 round 5 (ASTRA G5). There used to be a `sources_found`
            # fallback here: a mapping with a non-zero source count and NO
            # coverage axis was read as complete. That is the invariant this
            # module documents, contradicted three lines below where it is
            # stated -- and it is round 4's own lesson (`aggregate`'s docstring:
            # a non-empty source list proves content was PRODUCED, never that
            # every requested component was INSPECTED) left un-applied to the
            # normalizer itself. Removed. Every producer in this package sets an
            # explicit axis; a caller that does not gets "not inspected".
            extraction_complete = False
    extraction_complete = bool(extraction_complete)

    # Invariant 4. `needs_deep_scan` is a bool on the scan_auto notice and a LIST
    # of deferred attachments on the email aggregate; both mean the same thing --
    # bytes we have not read yet -- so both defeat completeness. Truthiness covers
    # both shapes; iterating did not, and a bool is not iterable.
    if warnings:
        extraction_complete = False
    if obj.get("needs_deep_scan"):
        extraction_complete = False

    inspection_complete = extraction_complete and not truncated

    return {
        "threat_found": threat_found,
        "inspection_complete": inspection_complete,
        "is_clean": (not threat_found) and inspection_complete,
        "extraction_complete": extraction_complete,
        "truncated": truncated,
        "warnings": warnings,
        "findings": list(findings),
        "decision": obj.get("decision") or ("block" if threat_found else "allow"),
        "severity": obj.get("severity") or _worst_severity(findings),
        "source": source if source is not None else obj.get("file") or obj.get("source"),
        "channel": obj.get("channel") or "file",
        "event_id": obj.get("event_id") or "",
        "latency_ms": obj.get("latency_ms") or 0.0,
    }


def normalize(obj: Any, *, source: Optional[str] = None, extra: Optional[dict] = None) -> dict:
    """Return the canonical result dict for any scan output in this package.

    Accepts an ``engine.ScanResult``, a scanner aggregate dict, a deep-scan dict,
    or a dependency-warning dict. Returns a plain dict carrying every key in
    ``CANONICAL_KEYS``.

    ``extra`` merges caller-owned presentation keys (``file``, ``sources``,
    ``results``, ...) UNDER the canonical ones, so a consumer can keep its own
    fields without ever being able to overwrite an axis. That ordering is the
    point: this function is not a suggestion the caller may override.
    """
    if isinstance(obj, dict):
        core = _normalize_mapping(obj, source)
        passthrough = {k: v for k, v in obj.items() if k not in CANONICAL_KEYS}
    elif _is_scan_result(obj):
        core = _normalize_scanresult(obj, source)
        passthrough = {}
    else:
        # Round-4 hardening (ASTRA's API observation). `getattr(obj, ..., default)`
        # meant `normalize(None)` and `normalize(object())` came back complete and
        # CLEAN: every axis defaulted to the optimistic value because nothing
        # contradicted it. Silence is not a pass -- and an input this function does
        # not understand is not silence, it is a caller bug. Refuse it loudly rather
        # than answer a question about a scan that never happened.
        raise TypeError(
            f"normalize() accepts a ScanResult or a scan-result mapping, "
            f"got {type(obj).__name__}. An unrecognised object is not a clean scan."
        )

    merged = dict(passthrough)
    if extra:
        merged.update({k: v for k, v in extra.items() if k not in CANONICAL_KEYS})
    merged.update(core)
    return merged


def _is_scan_result(obj: Any) -> bool:
    """Does this object carry the ScanResult surface ``normalize`` reads?

    ``findings`` is the discriminator: every result shape in this package has it,
    and nothing else that gets handed to ``normalize`` does.
    """
    return hasattr(obj, "findings")


def aggregate(children, *, source: Optional[str] = None,
              warnings=None, extraction_complete: bool = True,
              extra: Optional[dict] = None) -> dict:
    """Fold N child scans into ONE canonical document, losing no child's coverage.

    WHY THIS EXISTS (v0.5.6 repair, round 4).
    -----------------------------------------
    Round 3 gave every CONSUMER one place to decide "was it clean". Round 4 is the
    same fix one layer down, on the PRODUCERS. Five extractor ``scan_*`` convenience
    functions and two scanner helpers each built their own per-source dictionaries
    out of the child ``ScanResult`` -- copying ``decision``, ``severity`` and
    ``findings``, and dropping ``truncated`` and ``extraction_complete`` on the
    floor. ``normalize()`` then saw an aggregate that had never been told about the
    loss, and could only report what it was given.

    That is how a 1.2 M-character transcript with ``truncated: true`` on the engine
    child came back through ``scan_deep()`` as ``inspection_complete: true,
    is_clean: true, exit 0``: the truncation was real, was recorded, and was
    discarded one frame above the normalizer.

    THE INVARIANT, stated once so it cannot be re-derived per producer:

        A non-empty ``sources`` list proves that content was PRODUCED.
        It never proves that every requested component was INSPECTED.

    So coverage folds pessimistically and findings fold additively:

      * ``truncated``            -- any child truncated  => True
      * ``extraction_complete``  -- every child complete AND the extractor reported
                                    no failures AND no warnings were raised => True
      * ``warnings``             -- the caller's, plus every child's, concatenated
      * ``findings``             -- every child's, concatenated

    ``children`` is an iterable of ``(label, text, result)`` triples, where
    ``result`` is an ``engine.ScanResult``. The per-source ``results`` list this
    builds keeps the fields the previous aggregates published (``source``,
    ``text_preview``, ``decision``, ``severity``, ``findings``) so existing callers
    keep working, and ADDS the two coverage fields they used to discard, so the
    loss is visible per source and not only in the fold.
    """
    per_source = []
    findings: list = []
    folded_warnings = _as_list(warnings)
    truncated = False
    complete = bool(extraction_complete)
    threat_found = False
    scanned_bytes = 0

    for label, text, result in children:
        # v0.5.6 round 5 (ASTRA G5): this summed the EXTRACTED length, so a source
        # longer than the engine's cap was published as though all of it had been
        # inspected -- a number about what we handed the engine, printed as a
        # statement about what the engine read. The child knows the real figure
        # because the cap is applied before it counts.
        scanned_bytes += int(getattr(result, "bytes_scanned", None) or len(text or ""))
        child = normalize(result, source=label)
        preview = text if len(text) <= 100 else text[:100] + "..."
        per_source.append({
            "source": label,
            "text_preview": preview,
            "decision": child["decision"],
            "severity": child["severity"],
            "findings": child["findings"],
            # The two fields every previous aggregate dropped.
            "truncated": child["truncated"],
            "inspection_complete": child["inspection_complete"],
        })
        findings.extend(child["findings"])
        if child["truncated"]:
            truncated = True
        if not child["extraction_complete"]:
            complete = False
        if child["threat_found"]:
            threat_found = True
        for warning in child["warnings"]:
            if warning not in folded_warnings:
                folded_warnings.append(warning)

    merged_extra = dict(extra or {})
    merged_extra.setdefault("sources_found", len(per_source))
    # How much text actually reached the engine. An empty input is fully inspected
    # -- 0 of 0 bytes -- and that is a true, clean result; but a reader must be able
    # to tell a clean scan of a document from a clean scan of nothing, so the count
    # is published rather than left to be inferred from silence.
    merged_extra.setdefault("bytes_scanned", scanned_bytes)
    merged_extra["sources"] = [row["source"] for row in per_source]
    merged_extra["results"] = per_source
    # Kept for callers that predate the canonical name.
    merged_extra["threats"] = list(findings)

    return normalize(
        {
            "threat_found": threat_found,
            "extraction_complete": complete,
            "truncated": truncated,
            "warnings": folded_warnings,
            "findings": findings,
            "channel": "file",
        },
        source=source,
        extra=merged_extra,
    )


class NormalizedResult:
    """Attribute view over a normalized dict, for ``to_sarif``.

    ``to_sarif`` reads attributes. Rather than each caller inventing a shim -- the
    ``_Shim`` that shipped without ``channel``/``event_id``/``latency_ms`` and
    crashed the moment a finding existed -- there is one adapter, built from the
    normalized dict, so every field ``to_sarif`` touches is guaranteed present.
    """

    __slots__ = tuple(CANONICAL_KEYS) + ("extraction_warnings", "_data")

    def __init__(self, data: dict):
        self._data = dict(data)
        for key in CANONICAL_KEYS:
            setattr(self, key, self._data.get(key))
        # `to_sarif` and the reporter read this name for the same list.
        self.extraction_warnings = list(self._data.get("warnings") or [])

    def reported_findings(self) -> list:
        return list(self.findings or [])

    def to_dict(self) -> dict:
        return dict(self._data)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (f"NormalizedResult(threat_found={self.threat_found}, "
                f"inspection_complete={self.inspection_complete}, "
                f"is_clean={self.is_clean})")
