#!/usr/bin/env python3
"""
pattern-forge — ONE deterministic pattern validator. Built T8 (Opus 4.8) Jun 12 2026
from T9/Fable's FORGE_SPEC.md. Same exam everywhere: Jack's container, next-ship promote,
ship preflight. Pure stdlib + the sunglasses package. No model calls. No network.

Usage:
  python3 pattern_forge.py check <card.json|bundle.json> [--json]
  python3 pattern_forge.py regrade <dir> [--json]
Exit 0 = all green · exit 1 = at least one card failed.

Stages (fail-fast per card; all failures within the failed stage are reported):
  S1 schema-lint · S2 keyword-lint (FP killer) · S3 fp-gate (fp_gate.fp_offenders) ·
  S4 dedup (id+regex-signature vs live/NEXT_SHIP/pool) · S5 id-normalize (canonical + collision bump)

NOTE (deviation from spec, flagged to T9): valid-category authority is the IDnormalization
prefix_map.json (the category→prefix map), NOT build-patterns-page CHAPTER_META — CHAPTER_META
is keyed by chapter (ch01..) → title/slug, it has no flat category-name list. prefix_map IS the
canonical category set AND what S5 needs, so one source serves both. New category => WARN.
"""
import json, os, re, sys, argparse, glob

HERE = os.path.dirname(os.path.abspath(__file__))
PATTERNS_PY = os.path.join(HERE, "sunglasses", "patterns.py")
PREFIX_MAP = os.path.expanduser("~/.claude/skills/IDnormalization/scripts/prefix_map.json")
NEXT_SHIP = os.path.expanduser("~/jack-harvest/NEXT_SHIP")
POOL = os.path.expanduser("~/jack-harvest/pool")

CANON_ID = re.compile(r"^GLS-[A-Z0-9]+-\d+$")
ANY_ID = re.compile(r"GLS-[A-Z0-9]+-\d+")
PATH_CHARS = set("/.*_-")          # a short token is OK if it carries a path/extension/glob char
COMMON_WORDS = {"the","and","for","with","init","docs","doc","code","data","file","files",
                "agent","agents","note","notes","group","path","env","key","name","type",
                "user","tool","tools","api","run","get","set","add","use","ai"}

# ── field access (cards use final_id/final_category OR id/category) ────────────
def cid(c):  return c.get("final_id") or c.get("id")
def ccat(c): return (c.get("final_category") or c.get("category") or "").strip("`")
def creg(c):
    """regex field is a single string OR a list of strings in real cards — normalize to a list."""
    r = c.get("regex")
    if isinstance(r, str): return [r] if r.strip() else []
    if isinstance(r, list): return [x for x in r if isinstance(x, str) and x.strip()]
    return []

# ── data sources (cached) ─────────────────────────────────────────────────────
_cache = {}
def _prefix_data():
    if "pm" not in _cache:
        try: _cache["pm"] = json.load(open(PREFIX_MAP))
        except Exception: _cache["pm"] = {}
    return _cache["pm"]

def valid_categories():
    cats = set()
    for sec, v in _prefix_data().items():
        if isinstance(v, dict):
            for k, val in v.items():
                if not k.startswith("_") and isinstance(val, str) and not val.startswith(("MERGE", "RENAME")):
                    cats.add(k)
    return cats

def category_prefix_map():
    m = {}
    for sec, v in _prefix_data().items():
        if isinstance(v, dict):
            for k, val in v.items():
                if not k.startswith("_") and isinstance(val, str) and not val.startswith(("MERGE", "RENAME")):
                    m.setdefault(k, val)
    return m

def engine_denylist():
    try:
        from sunglasses.engine import SunglassesEngine
        dl = getattr(SunglassesEngine(), "KEYWORD_DENYLIST", None) or getattr(SunglassesEngine, "KEYWORD_DENYLIST", set())
        return {str(x).lower() for x in dl}
    except Exception:
        return set()

def live_ids():
    try: return set(ANY_ID.findall(open(PATTERNS_PY).read()))
    except Exception: return set()

def clean_corpus_raw():
    """Concatenated clean-code corpus from fp_gate (raw, case-preserved) — single source, cached once."""
    if "corpus_raw" not in _cache:
        try:
            import fp_gate
            _cache["corpus_raw"] = "\n".join(t for t, _ch in fp_gate.clean_samples())
        except Exception:
            _cache["corpus_raw"] = ""
    return _cache["corpus_raw"]

def clean_corpus_text():
    """Lowercased corpus for the S2 keyword substring pre-screen."""
    if "corpus" not in _cache:
        _cache["corpus"] = clean_corpus_raw().lower()
    return _cache["corpus"]

def engine_ok():
    """Can the real engine load? (S3 FP-parity is impossible without it.)"""
    try:
        from sunglasses.engine import SunglassesEngine
        SunglassesEngine()
        return True, ""
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"

# ── failure helper ────────────────────────────────────────────────────────────
def fail(stage, reason, fix_hint):
    return {"stage": stage, "reason": reason, "fix_hint": fix_hint}

# ── env gate (finding #1, F5 review): a forge that can't load its truth must SCREAM,
#    never emit a false GREEN. Empty corpus / dead engine / no live ids => HARD abort,
#    because S3, S2(d) and S4-vs-live all silently SKIP on empty sources otherwise
#    (host↔container #6 parity breaks invisibly inside Jack's container). ──────────
def env_check():
    """Return a list of FATAL environment failures (empty list == healthy)."""
    fatal = []
    ok, err = engine_ok()
    if not ok:
        fatal.append(fail("ENV", f"sunglasses engine will not load: {err}",
                          "fix install/import — S3 FP-parity is impossible without it"))
    if not clean_corpus_raw().strip():
        fatal.append(fail("ENV", "fp_gate clean corpus is EMPTY",
                          "fp_gate/tests not importable — S3 would falsely PASS every card"))
    if not live_ids():
        fatal.append(fail("ENV", "live patterns.py id set is EMPTY",
                          "patterns.py unreadable — S4/S5 dedup-vs-live would silently skip"))
    return fatal

# ── S1 schema-lint ────────────────────────────────────────────────────────────
def s1_schema(card, is_v3=False):
    out = []
    cid_v = cid(card)
    if not cid_v or not CANON_ID.match(str(cid_v)):
        out.append(fail("S1", f"id missing/non-canonical: {cid_v!r}", "use GLS-<PREFIX>-<NNN>"))
    name = (card.get("name") or "").strip()
    if not name:
        out.append(fail("S1", "name empty", "add a human name"))
    elif name == str(cid_v):
        out.append(fail("S1", "name equals id", "name must be descriptive, not the id"))
    cat = ccat(card)
    if not cat:
        out.append(fail("S1", "category empty", "set a category"))
    elif cat not in valid_categories():
        out.append(fail("S1-WARN", f"category '{cat}' not in canonical map", "new category needs a /patterns chapter + prefix_map entry"))
    sev = card.get("severity")
    sev_s = sev.strip().lower() if isinstance(sev, str) else ""
    if not sev_s:
        out.append(fail("S1", "severity missing", "set critical/high/medium/low"))
    elif sev_s not in {"critical", "high", "medium", "low"}:
        out.append(fail("S1", f"severity {sev!r} not in {{critical,high,medium,low}}", "use a canonical severity"))
    ch = card.get("channel")
    if not isinstance(ch, list) or not ch:
        out.append(fail("S1", "channel not a non-empty list", "e.g. [\"file\"]"))
    kws = card.get("keywords")
    if not isinstance(kws, list) or not kws:
        out.append(fail("S1", "keywords not a non-empty list", "add trigger keywords"))
    rgx = creg(card)
    if not rgx:
        out.append(fail("S1", "regex missing/empty", "add at least one regex (string or list)"))
    else:
        for r in rgx:
            try: re.compile(r)
            except Exception as e:
                out.append(fail("S1", f"regex does not compile: {r!r} ({e})", "fix the regex"))
    if not (card.get("description") or "").strip():
        out.append(fail("S1", "description empty", "add prose description"))
    if is_v3:
        for sec, mn in (("fixture_positive", 8), ("fixture_negative", 8)):
            v = card.get(sec)
            n = len(v) if isinstance(v, list) else 0
            if n < mn:
                out.append(fail("S1", f"{sec} has {n}, needs >={mn}", f"add {sec} fixtures"))
        if not card.get("validation_summary"):
            out.append(fail("S1", "validation_summary missing", "add validation_summary (V3 hard req)"))
    return out

# ── S2 keyword-lint (the FP killer — root-cause #1) ───────────────────────────
def s2_keywords(card):
    out = []
    denylist = engine_denylist()
    corpus = clean_corpus_text()
    for kw in (card.get("keywords") or []):
        if not isinstance(kw, str):
            out.append(fail("S2", f"non-string keyword: {kw!r}", "keywords must be strings")); continue
        k = kw.strip()
        low = k.lower()
        # (c) bare structural token / pure punctuation
        if not k or not any(ch.isalnum() for ch in k):
            out.append(fail("S2", f"keyword is punctuation/structural: {kw!r}", "drop it — fires on any file")); continue
        # (a) too short unless it carries a path/ext/glob char
        if len(k) < 4 and not any(ch in PATH_CHARS for ch in k):
            out.append(fail("S2", f"keyword too short/generic: {kw!r}", "drop or make specific (>=4 chars or a path token)")); continue
        # (b) denylist
        if low in denylist:
            out.append(fail("S2", f"keyword in engine KEYWORD_DENYLIST: {kw!r}", "this word floods clean code — drop it")); continue
        # (c) single common word
        if low in COMMON_WORDS:
            out.append(fail("S2", f"keyword is a generic common word: {kw!r}", "too broad — fires everywhere")); continue
        # (d) cheap corpus pre-screen — does this keyword appear in known-clean code?
        if corpus and len(k) >= 4 and low in corpus:
            out.append(fail("S2", f"keyword appears in clean-code corpus: {kw!r}", "will cause false positives — tighten or drop"))
    return out

# ── S3 fp-gate — TRUE host↔container parity (acceptance #6) ────────────────────
def s3_fpgate(card):
    """Acceptance #6: apply→scan→restore through fp_gate's REAL engine + corpus, never a
    re-implementation (hard rule #1). Temporarily register the candidate in the live PATTERNS
    list, ask fp_gate.fp_offenders({id}) whether it raises a BLOCKING finding on the curated
    clean corpus, then restore. Same verdict on host and inside Jack's container because both
    run the identical engine+corpus. (Replaces the round-1 regex-vs-corpus proxy.)
    Only BLOCKING-severity hits count as FPs — that IS the gate's definition, so a low-severity
    card can't be an FP by construction."""
    pid = cid(card)
    if not pid:
        return []  # S1 already failed a missing id
    try:
        import sunglasses.patterns as P
        import fp_gate
    except Exception as e:
        return [fail("S3", f"fp-gate/engine unavailable: {e}",
                     "forge cannot verify FP-safety — environment broken (see ENV gate)")]
    pat = {
        "id": pid,
        "name": card.get("name") or pid,
        "category": ccat(card) or "uncategorized",
        "severity": (card.get("severity") or "medium"),
        "channel": card.get("channel") or ["file"],
        "keywords": card.get("keywords") or [],
        "regex": creg(card),
        "description": card.get("description") or "",
    }
    P.PATTERNS.append(pat)
    try:
        offenders = fp_gate.fp_offenders(candidate_ids={pid})
    except Exception as e:
        return [fail("S3", f"fp_gate raised while scanning: {e}", "could not scan clean corpus")]
    finally:
        try: P.PATTERNS.remove(pat)
        except ValueError: pass
    if pid in offenders:
        return [fail("S3", "card raises a BLOCKING finding on clean corpus (fp_gate apply→scan→restore)",
                     "this pattern false-positives on legitimate code — tighten regex/keywords")]
    return []

# ── S4 dedup (id + regex-signature vs live / NEXT_SHIP / pool) ─────────────────
def _sig(card):
    return tuple(sorted(r.strip() for r in creg(card)))

def _known_ids_and_sigs():
    ids = live_ids()
    sigs = {}
    # finding #2 (F5 review): LIVE patterns.py regexes ARE signatures — a fresh id with a
    # regex copied from a shipped pattern must be caught. Seed sigs from live first.
    try:
        import sunglasses.patterns as _P
        for p in _P.PATTERNS:
            if isinstance(p, dict):
                s, pid = _sig(p), cid(p)
                if s and pid: sigs.setdefault(s, pid)
    except Exception:
        pass  # env_check() already hard-fails when the engine/patterns won't load
    for d in (NEXT_SHIP, POOL):
        for f in glob.glob(os.path.join(d, "*.json")):
            if any(x in f for x in ("MANIFEST", "_superseded", "NEXT_SHIP.json")): continue
            try: data = json.load(open(f))
            except Exception: continue
            pats = data.get("patterns", data if isinstance(data, list) else [])
            for p in pats if isinstance(pats, list) else []:
                if isinstance(p, dict):
                    pid = cid(p)
                    if pid: sigs.setdefault(_sig(p), pid)
    return ids, sigs

def s4_dedup(card, known=None, batch=None):
    out = []
    ids, sigs = known if known else _known_ids_and_sigs()
    cid_v = cid(card)
    sig = _sig(card)
    if cid_v and cid_v in ids:
        out.append(fail("S4", f"id {cid_v} already LIVE in patterns.py", "renumber or it's a dup ship"))
    if sig and sig in sigs and sigs[sig] != cid_v:
        out.append(fail("S4", f"regex-signature duplicates {sigs[sig]}", "this pattern already exists under another id"))
    # finding #3 (F5 probe: two identical cards in one bundle both passed) — dedup WITHIN the batch
    if batch is not None:
        if cid_v and cid_v in batch["ids"]:
            out.append(fail("S4", f"id {cid_v} duplicates an earlier card in this same bundle", "ids must be unique within a bundle"))
        if sig and sig in batch["sigs"] and batch["sigs"][sig] != cid_v:
            out.append(fail("S4", f"regex-signature duplicates earlier card {batch['sigs'][sig]} in this same bundle", "two cards carry identical regex"))
        if cid_v: batch["ids"].setdefault(cid_v, True)
        if sig: batch["sigs"].setdefault(sig, cid_v)
    return out

# ── S5 id-normalize (canonical form + collision bump) ─────────────────────────
def s5_idnorm(card, live=None):
    out = []
    cid_v = cid(card)
    cat = ccat(card)
    pmap = category_prefix_map()
    if cat in pmap:
        want = pmap[cat]
        if cid_v and not str(cid_v).startswith(f"GLS-{want}-"):
            out.append(fail("S5", f"id {cid_v} prefix != category prefix '{want}' for '{cat}'",
                            f"normalize to GLS-{want}-<NNN>"))
    elif cat:
        out.append(fail("S5-WARN", f"no prefix mapping for category '{cat}'", "add to prefix_map.json"))
    return out

# ── per-card driver (fail-fast) ───────────────────────────────────────────────
def check_card(card, is_v3=False, known=None, run_fp=True, batch=None):
    for stage_fn, args in [(s1_schema, (card, is_v3)), (s2_keywords, (card,)),
                           (s3_fpgate, (card,)) if run_fp else (lambda c: [], (card,)),
                           (s4_dedup, (card, known, batch)), (s5_idnorm, (card,))]:
        fails = stage_fn(*args)
        # S*-WARN entries don't fail the card; collect but continue
        hard = [f for f in fails if not f["stage"].endswith("WARN")]
        warns = [f for f in fails if f["stage"].endswith("WARN")]
        if hard:
            return {"card": cid(card), "ok": False, "stage": hard[0]["stage"], "failures": hard, "warnings": warns}
    return {"card": cid(card), "ok": True, "stage": None, "failures": [], "warnings": []}

# ── input loading (json bundle/card; .md V3 card best-effort) ──────────────────
def load_cards(path):
    if path.endswith(".json"):
        data = json.load(open(path))
        pats = data.get("patterns", data if isinstance(data, list) else [data])
        return [(p, False) for p in pats if isinstance(p, dict)]
    return []  # .md V3 parsing: next iteration

# ── CLI ───────────────────────────────────────────────────────────────────────
def _print_env(env, as_json):
    if as_json:
        print(json.dumps({"error": "FORGE ENVIRONMENT BROKEN — refusing to grade (would emit false GREEN)",
                          "env_failures": env}, indent=2))
    else:
        print("⛔ FORGE ENVIRONMENT BROKEN — refusing to grade (would emit a false GREEN):")
        for f in env:
            print(f"     - [{f['stage']}] {f['reason']}  →  {f['fix_hint']}")

def cmd_check(args):
    env = env_check()
    if env:
        _print_env(env, args.json); return 2
    cards = load_cards(args.path)
    if not cards:
        print(json.dumps({"error": f"no cards loaded from {args.path}"})); return 1
    known = _known_ids_and_sigs()
    batch = {"ids": {}, "sigs": {}}
    results = [check_card(c, is_v3=v3, known=known, batch=batch) for c, v3 in cards]
    bad = [r for r in results if not r["ok"]]
    if args.json:
        print(json.dumps({"checked": len(results), "failed": len(bad), "results": results}, indent=2))
    else:
        for r in results:
            tag = "✅ PASS" if r["ok"] else f"❌ FAIL @ {r['stage']}"
            print(f"{tag}  {r['card']}")
            for f in r["failures"]:
                print(f"     - [{f['stage']}] {f['reason']}  →  {f['fix_hint']}")
        print(f"\n{len(results)-len(bad)}/{len(results)} green.")
    return 1 if bad else 0

def cmd_regrade(args):
    env = env_check()
    if env:
        _print_env(env, args.json); return 2
    files = sorted(glob.glob(os.path.join(args.path, "*.json")))
    known = _known_ids_and_sigs()
    run_fp = getattr(args, "fp", False)   # bulk regrade is structural by default; --fp adds true S3 (slow)
    report = []
    for f in files:
        if any(x in f for x in ("MANIFEST", "NEXT_SHIP.json")): continue
        try: cards = load_cards(f)
        except Exception as e:
            report.append({"file": os.path.basename(f), "error": str(e)}); continue
        batch = {"ids": {}, "sigs": {}}
        rs = [check_card(c, is_v3=v3, known=known, run_fp=run_fp, batch=batch) for c, v3 in cards]
        report.append({"file": os.path.basename(f), "cards": len(rs),
                       "green": sum(1 for r in rs if r["ok"]), "failed": sum(1 for r in rs if not r["ok"])})
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for r in report:
            if "error" in r: print(f"  ⚠️  {r['file']}: {r['error']}")
            else: print(f"  {r['green']:>3}/{r['cards']:<3} green  {r['file']}  ({r['failed']} failed)")
    return 0

if __name__ == "__main__":
    ap = argparse.ArgumentParser(prog="pattern-forge")
    ap.add_argument("--json", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    c = sub.add_parser("check"); c.add_argument("path"); c.add_argument("--json", action="store_true")
    g = sub.add_parser("regrade"); g.add_argument("path"); g.add_argument("--json", action="store_true")
    g.add_argument("--fp", action="store_true", help="run true S3 fp-gate per card (slow; structural-only by default)")
    a = ap.parse_args()
    if a.cmd == "check": sys.exit(cmd_check(a))
    elif a.cmd == "regrade": sys.exit(cmd_regrade(a))
    else: ap.print_help(); sys.exit(2)
