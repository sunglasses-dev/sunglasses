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
    for path in sorted(PACKAGE.glob("*.py")):
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
