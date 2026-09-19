"""R-CLOSE-KIND: the map from close SITES to cause kinds, asserted.

Two `(reason, rule)` pairs covered twelve of this package's close sites, so a
receipt could say a protocol fault ended the session and never which one. The
fix is a `cause_kind` from a frozen catalog. These rows are the gate that keeps
it honest, and they read the SOURCE rather than the behaviour, because a close
site added next month will not be in anybody's test until it is.

THE TEST IS THE GUARANTEE, NOT A TYPEERROR. `_close` takes `kind` with a
default of None on purpose: making it required was measured first and it breaks
six of the reviewer's controls -- including another PR's acceptance file -- and
21 of our own rows, because a control drives a close positionally to prove what
happens when one lands mid-flight. A TypeError that fires only inside a harness
is not a guarantee, it is a broken instrument.
"""
import ast
import pathlib

import pytest

from sunglasses.proxy.session import CAUSE_KINDS

PACKAGE = pathlib.Path(__file__).resolve().parents[2] / "sunglasses" / "proxy"


def _close_sites():
    """Every `_close(...)` CALL in the package, once, with how its kind is
    supplied and the parameters of the function it sits in.

    The enclosing function comes with it because one legitimate source is a
    PASS-THROUGH: `Route._close` takes a kind and hands it to the session's.
    Judging that bare name without knowing it is the enclosing parameter would
    either reject a correct site or accept any local called `kind`.

    Each call is yielded ONCE. The first draft walked every function scope and
    `ast.walk` from an outer scope reaches inner calls too, so every site in a
    method appeared twice and the one-fault-one-kind row read four sites where
    there are two. A control that miscounts is worse than no control here,
    because this file exists to count.
    """
    # M07. RECURSIVE. `glob("*.py")` reads the package's top level only, so a
    # close site in a nested module was never looked at -- the reviewer added
    # one and all ten author rows stayed green. A guard over "the package" that
    # silently means "the top of the package" is the shape this file exists to
    # refuse.
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text())
        scope = {}
        for node in ast.walk(tree):
            params = set()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params = {a.arg for a in node.args.args + node.args.kwonlyargs}
            for child in ast.iter_child_nodes(node):
                scope[child] = params or scope.get(node, set())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if getattr(node.func, "attr", "") != "_close":
                continue
            kind = next((k.value for k in node.keywords if k.arg == "kind"),
                        None)
            yield path.name, node.lineno, kind, scope.get(node, set())


def test_every_close_site_supplies_a_kind():
    """A new close site fails HERE, by name, rather than shipping a receipt
    that cannot say which fault ended the session."""
    missing = [f"{name}:{line}" for name, line, kind, _ in _close_sites()
               if kind is None]
    assert not missing, (
        f"these close sites supply no cause_kind: {missing}. Add one from the "
        f"catalog in session.py, or pass through the kind from the result that "
        f"produced the reason.")


def test_every_kind_source_is_a_literal_or_a_result_field():
    """Two shapes and no third. A literal for a fault this site recognises, or
    a field of the result that produced the reason -- `parsed.kind`,
    `negotiated.kind`, `frame.kind`. Anything else is a caller choosing a kind
    for a fault it did not diagnose, which is a field that can lie."""
    bad = []
    for name, line, kind, params in _close_sites():
        if isinstance(kind, ast.Constant) and isinstance(kind.value, str):
            continue
        if isinstance(kind, ast.Attribute) and kind.attr == "kind":
            continue
        if isinstance(kind, ast.Name) and kind.id in params:
            continue                  # a pass-through of the caller's own kind
        if kind is not None:
            bad.append(f"{name}:{line} -> {ast.unparse(kind)}")
    assert not bad, bad


def test_every_literal_kind_is_in_the_catalog():
    unknown = sorted({kind.value for _, _, kind, _ in _close_sites()
                      if isinstance(kind, ast.Constant)} - CAUSE_KINDS)
    assert not unknown, (
        f"{unknown} are not in the frozen catalog; a receipt field that is not "
        f"from a fixed vocabulary cannot be compared to a fixture")


def test_one_fault_one_kind_wherever_the_code_is_standing():
    """Two sites may share a kind ONLY because they are the same fault.

    `pump.py` closes with "the upstream process exited with calls still
    pending" at one site and "upstream exited with calls still pending" at
    another. Two sentences, one fault, one kind. This row exists so that the
    next person who adds a close for THAT fault reuses the kind instead of
    inventing a synonym, which would put the catalog back where the reason
    catalog already is.
    """
    shared = {}
    for name, line, kind, _ in _close_sites():
        if isinstance(kind, ast.Constant):
            shared.setdefault(kind.value, []).append(f"{name}:{line}")
    expected = {
        "ID_REUSED_WHILE_SETTLING": 2,     # client and upstream, same fault
        "ID_REUSED_WHILE_PENDING": 2,      # client and upstream, same fault
        "UPSTREAM_EXIT_WITH_PENDING": 2,   # two sites, two sentences, one fault
        # A frame that ended without its terminator, from either direction:
        # pump.py reads it of the upstream (MALFORMED_UPSTREAM, "the last frame
        # ended without its terminator") and serve.py of the client
        # (MALFORMED_CLIENT, "the client stopped in the middle of a frame").
        # Same fault, opposite origins, which is the ID_REUSED_WHILE_* shape
        # two lines up -- the REASON carries the direction and the kind carries
        # the fault. Found by this row when the serve.py site was wired, which
        # is the row working rather than the row being edited around.
        "FRAME_UNTERMINATED": 2,
    }
    for kind, sites in shared.items():
        if len(sites) > 1:
            assert kind in expected, (
                f"{kind} fires at {sites}; if those are the same fault add it "
                f"to the expected map with the reason, and if they are not, "
                f"they need different kinds")
            assert len(sites) == expected[kind], (kind, sites)

    # M06, AND THIS DIRECTION IS THE ONE THAT WAS MISSING. Everything above
    # only inspects kinds that STILL appear more than once, so SPLITTING a
    # declared pair -- giving one of its two sites a synonym -- drops both
    # halves to one site each and slips under every assertion. The reviewer
    # did exactly that and all ten author rows stayed green.
    #
    # A declared pair is a claim that N sites share one fault. The claim is
    # false the moment the count is anything but N, in either direction.
    for kind, count in sorted(expected.items()):
        actual = shared.get(kind, [])
        assert len(actual) == count, (
            f"{kind} is declared as {count} sites that are the same fault and "
            f"fires at {len(actual)}: {actual}. A site that left the pair took "
            f"a synonym for a fault that already has a word, which is the "
            f"reason catalog's defect moved into the kind catalog")


@pytest.mark.parametrize("module,attribute", [
    ("framing", "kind"), ("handshake", "kind"), ("bounds", "kind"),
])
def test_the_results_that_carry_a_reason_also_carry_a_kind(module, attribute):
    """The kind is produced where the REASON is produced. A site that takes one
    from a result must be able to take the other from the same object."""
    import importlib
    loaded = importlib.import_module(f"sunglasses.proxy.{module}")
    holder = {"framing": "Frame", "handshake": "Negotiation",
              "bounds": "Breach"}[module]
    assert attribute in getattr(loaded, holder).__slots__


def test_the_only_reason_that_closes_without_a_kind_is_over_budget():
    """The one fault whose result deliberately carries no kind, named BY FAULT.

    `bounds.Breach` reaches a close site through several reasons, and
    OVER_BUDGET is the one that carries `kind=None` on purpose: `budget`
    already names which limit broke and it reaches the receipt, so a kind would
    describe the same thing twice. framing.py records the identical decision
    for its own OVER_BUDGET returns.

    THIS ROW EXISTS SO THE EXEMPTION IS A STATEMENT ABOUT A FAULT AND NOT ABOUT
    A PLACE. Written as "pump.py:1050 may pass None" it would go stale the
    moment a line moved, say nothing about a second over-budget close added
    elsewhere, and excuse any future kindless close that landed on that line.

    EVERY CONSTRUCTOR IS READ, NOT WHETHER THE REASON APPEARS SOMEWHERE. The
    first draft asserted `"OVER_BUDGET" in kindless`, and a control that gave
    check_content's OVER_BUDGET a kind PASSED -- check_frame's is also
    kindless, so the membership held while the fact it stood for had stopped
    being true. A set says a reason exists kindless SOMEWHERE; the exemption
    is that it is kindless EVERYWHERE.
    """
    source = ast.parse((PACKAGE / "bounds.py").read_text())
    kinds_by_reason = {}
    for node in ast.walk(source):
        if not (isinstance(node, ast.Call)
                and getattr(node.func, "id", "") == "Breach"
                and node.args):
            continue
        reason = node.args[0]
        if not (isinstance(reason, ast.Constant) and isinstance(reason.value, str)):
            continue
        kind = next((k.value for k in node.keywords if k.arg == "kind"), None)
        value = kind.value if isinstance(kind, ast.Constant) else kind
        kinds_by_reason.setdefault(reason.value, set()).add(value)

    assert kinds_by_reason.get("OVER_BUDGET") == {None}, (
        f"every OVER_BUDGET breach must carry kind=None and these carry "
        f"{sorted(map(str, kinds_by_reason.get('OVER_BUDGET', ())))}; if one "
        f"gaining a kind is deliberate, this row and the paragraph in "
        f"bounds.py both have to say so")

    # Reasons that never reach a close site are not exempt, they are simply
    # not there yet: if one is wired to a close later it needs a kind before
    # it arrives, not a line added here.
    NEVER_CLOSES = {"OVERLOADED", "APPROVAL_REQUIRED"}
    for reason, kinds in sorted(kinds_by_reason.items()):
        if reason == "OVER_BUDGET" or reason in NEVER_CLOSES:
            continue
        assert None not in kinds, (
            f"{reason} produces a close with no kind. Only OVER_BUDGET is "
            f"exempt, and only because `budget` already carries the fact")
    assert kinds_by_reason.get("SCAN_DEADLINE") == {"DEADLINE_EXPIRED"}


# ---------------------------------------------------------------------------
# R-185-R5. The four rows below each exist because a NAMED mutant walked past
# everything above it. Each one is the assertion that mutant needed, and no
# wider: the reviewer's M04, M05, M06 and M08.
# ---------------------------------------------------------------------------

THE_CATALOG = frozenset({
    "ID_NAMESPACE_CLAIMED", "ID_REUSED_WHILE_SETTLING", "ID_REUSED_WHILE_PENDING",
    "RESPONSE_NOT_PENDING", "RESPONSE_SHAPE_MISMATCH", "UPSTREAM_EXIT_WITH_PENDING",
    "FRAME_UNTERMINATED", "INITIALIZE_RESULT_SHAPE", "TOMBSTONE_TABLE_FULL",
    "HANDOFF_GENERATION_MISMATCH", "FRAME_INVALID_UTF8", "FRAME_JSON_CONSTANT",
    "FRAME_DUPLICATE_KEY", "FRAME_UNPARSEABLE", "FRAME_TOP_LEVEL_NOT_OBJECT",
    "FRAME_JSONRPC_VERSION", "FRAME_ENVELOPE_INVALID", "FRAME_ID_TYPE",
    "PROTOCOL_VERSION_UNSUPPORTED", "CLIENT_RESPONSE_UNSOLICITED",
    "DEADLINE_EXPIRED", "WATCHDOG_FAILED", "DECISION_AUTHORITY_MOVED",
    "RECEIPT_WRITE_FAILED",
})


def test_the_catalog_is_pinned_here_not_only_validated_at_construction():
    """M06. The catalog is a CLOSED SET, so adding to it is a decision.

    `Cause` validates membership when one is constructed, which stops an
    uncatalogued kind reaching a receipt but says nothing about the catalog
    itself growing. The reviewer added a synonym to `CAUSE_KINDS` and used it
    at one site; every row passed, because each one asked "is this kind in the
    catalog" and the answer had just been made yes.

    A pin costs one line per kind and turns catalog growth into an edit
    somebody has to justify here, which is what a fixed vocabulary means.
    """
    assert CAUSE_KINDS == THE_CATALOG, {
        "added without declaring": sorted(CAUSE_KINDS - THE_CATALOG),
        "declared but gone": sorted(THE_CATALOG - CAUSE_KINDS),
    }
    assert len(THE_CATALOG) == 24


def test_the_receipt_field_set_is_exactly_the_four_fixed_vocabularies():
    """M04. `Cause.as_receipt()` is an ALLOWLIST, asserted as a whole set.

    The reviewer put `detail` back into it. Nothing went red: the map rows read
    source and never call it, and the writer's own field filter drops `detail`
    on the way to disk, so the author's disk assertion could not see the
    regression either. Two guards, each blind in the direction the other
    covered, and between them a prose field back in the event stream.

    This asserts the RETURNED KEYS, exactly, so a fifth field of any name fails
    here whatever the writer would later do with it. `detail` is named
    separately because it is the specific field that leaked peer material into
    a receipt twice.
    """
    from sunglasses.proxy.session import Cause
    cause = Cause("MALFORMED_UPSTREAM", "S5", budget=None,
                  detail="peer-supplied prose that must never reach evidence",
                  kind="FRAME_UNTERMINATED")
    receipt = cause.as_receipt()
    assert set(receipt) == {"reason_code", "rule", "budget", "cause_kind"}, receipt
    assert "detail" not in receipt
    assert cause.detail  # still on the object, for logs and exceptions
    assert receipt["cause_kind"] == "FRAME_UNTERMINATED"


def test_the_kind_is_on_the_disk_allowlist_and_the_prose_is_on_the_never_list():
    """M05. The durable receipt keeps only what `PERMITTED_FIELDS` names.

    Dropping `cause_kind` from that list leaves every in-memory assertion
    green and silently removes the field from disk -- which is how the field
    was discovered missing in the first place, by writing a row and reading it
    back. The author's own disk row catches this; the map file could not, and
    the two are different instruments that should not depend on each other.
    """
    from sunglasses.proxy import receipts
    assert "cause_kind" in receipts.PERMITTED_FIELDS, (
        "a kind the session carries but the writer drops is a change that "
        "looks complete and alters nothing a reader ever sees")
    assert "detail" in receipts.FORBIDDEN_FIELDS
    assert not (receipts.PERMITTED_FIELDS & receipts.FORBIDDEN_FIELDS)


@pytest.mark.parametrize("module,holder", [
    ("framing", "Frame"), ("handshake", "Negotiation"), ("bounds", "Breach"),
])
def test_every_producer_kind_VALUE_is_in_the_catalog(module, holder):
    """M08. A slot existing is not its values belonging to the vocabulary.

    `test_the_results_that_carry_a_reason_also_carry_a_kind` asserts these
    holders HAVE a `kind` slot. The reviewer replaced framing's UTF-8 fault
    kind with an uncatalogued literal and every row stayed green, including
    those producer rows: the slot was still there, and the close sites that
    pass it through do so by attribute, so no literal appears at a call site
    for the catalog row to read.

    So the literals are read HERE, at the producer, where they are written.
    `None` is allowed and is the documented OVER_BUDGET exemption, asserted by
    fault one row below.
    """
    source = ast.parse((PACKAGE / f"{module}.py").read_text())
    literals = []
    for node in ast.walk(source):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg != "kind":
                continue
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                literals.append((node.lineno, keyword.value.value))
    outside = sorted({v for _, v in literals} - CAUSE_KINDS)
    assert not outside, (
        f"{module}.py produces {outside} as a cause kind and the catalog does "
        f"not contain it; a receipt field that is not from a fixed vocabulary "
        f"cannot be compared to a fixture")
    assert literals, (
        f"no kind literal found in {module}.py -- this row would pass on a "
        f"module that produces no kinds at all, so it asserts it found some")
