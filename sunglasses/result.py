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

__all__ = ["normalize", "CANONICAL_KEYS", "NormalizedResult"]


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
        elif obj.get("sources_found") is not None:
            # A transcript that never existed inspected nothing.
            extraction_complete = bool(obj.get("sources_found"))
        else:
            # Invariant 2: silence is not a pass.
            extraction_complete = False
    extraction_complete = bool(extraction_complete)

    # Invariant 4, twice over.
    if warnings:
        extraction_complete = False
    if obj.get("needs_deep_scan"):
        extraction_complete = False
    for pending in obj.get("needs_deep_scan") or []:
        if isinstance(pending, dict):
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
    else:
        core = _normalize_scanresult(obj, source)
        passthrough = {}

    merged = dict(passthrough)
    if extra:
        merged.update({k: v for k, v in extra.items() if k not in CANONICAL_KEYS})
    merged.update(core)
    return merged


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
