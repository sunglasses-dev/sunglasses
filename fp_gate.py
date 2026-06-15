#!/usr/bin/env python3
"""
fp_gate.py — THE shared false-positive gate for Sunglasses. Jun 12 2026 (Opus 4.8).

ONE gate, callable everywhere: next-ship `promote`, ship preflight, AND Jack's
Pattern-Forge (in-container). Import it — do NOT reimplement the corpus.

    from fp_gate import fp_offenders
    offenders = fp_offenders(candidate_ids={"GLS-DFP-097", ...})   # empty set == clean pass

Truth model (mirrors tests/test_false_positives.py + tests/test_real_corpus_fp.py exactly):
  - Clean corpus = the CURATED CLEAN_CORPUS list + the known-clean stdlib files the
    real-corpus test uses. NOT a naive scrape of every string in the test module
    (that would wrongly include attack canaries / should-block fixtures).
  - An OFFENDER = a finding with BLOCKING severity (critical/high/medium) on clean
    content. Low/info findings are not false positives. This matches the tests'
    `blocking = [f for f ... if severity in (...)]` assertion.
Run from the glasses/ dir (so `sunglasses` and `tests` import).
"""
BLOCKING = ("critical", "high", "medium")


def clean_samples():
    """(text, channel) pairs that MUST scan clean — the curated FP corpus only.
    Sourced from fp_corpus_data (the pytest-free single source) so this gate — and
    Pattern-Forge built on it — runs inside Jack's container with no test deps.
    Decoupled from the test modules Jun 12 2026 (Opus 4.8) per F5 warroom ruling."""
    out = []
    try:
        import fp_corpus_data as d
        for item in d.CLEAN_CORPUS:          # (name, text, channel)
            out.append((item[1], item[2]))
        for path in d.clean_files():         # known-clean real files (decoder.py, encoder.py)
            try:
                out.append((open(path, errors="ignore").read(), "file"))
            except Exception:
                pass
    except Exception:
        pass
    return out


def _fid_sev(f):
    if isinstance(f, dict):
        return f.get("id"), f.get("severity")
    return getattr(f, "id", None), getattr(f, "severity", None)


def fp_offenders(candidate_ids=None, extra_samples=None):
    """Set of pattern IDs that raise a BLOCKING finding on clean code. Empty == gate pass.
    candidate_ids: if given, intersect offenders with these (only care about new patterns).
    extra_samples: iterable of clean-code strings (scanned as channel='file')."""
    from sunglasses.engine import SunglassesEngine
    eng = SunglassesEngine()
    samples = clean_samples() + [(s, "file") for s in (extra_samples or [])]
    off = set()
    for text, channel in samples:
        res = eng.scan(text, channel=channel)
        for f in res.findings:
            fid, sev = _fid_sev(f)
            if fid and sev in BLOCKING:
                off.add(fid)
    if candidate_ids is not None:
        off &= set(candidate_ids)
    return off


if __name__ == "__main__":
    import json, sys
    cands = set(sys.argv[1:]) or None
    print("FP_OFFENDERS=" + json.dumps(sorted(fp_offenders(candidate_ids=cands))))
