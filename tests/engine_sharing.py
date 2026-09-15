"""Helpers for modules that share one engine.

These live here rather than in `conftest.py` because tests IMPORT them, and a
conftest is collected by pytest rather than imported by name. There are two
conftest modules in this tree (the root one holding fixtures, and tests/ naming
the tree a run happened on), so `from conftest import ...` resolves to whichever
pytest put on the path first. It resolved to the wrong one on the first attempt.
"""

def module_documents(module, minimum_length=40):
    """Every fixture document a module defines, by name.

    Read off the module rather than listed by hand, so a document added later is
    covered by the statelessness control automatically and a hand-written list
    cannot quietly stop describing the file.

    Upper-case LISTS and TUPLES are walked too, not only bare strings. The first
    version collected only strings and found zero documents in a module that
    keeps its payloads in a list, which the vacuity guard below caught rather
    than letting the control pass over nothing.
    """
    found = {}
    for name, value in vars(module).items():
        if not name.isupper():
            continue
        if isinstance(value, str) and len(value) > minimum_length:
            found[name] = value
        elif isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                if isinstance(item, str) and len(item) > minimum_length:
                    found[f"{name}[{index}]"] = item
    return found


def assert_engine_is_stateless(engine, documents, channel="file", minimum=3):
    """One engine, every document, forwards and then backwards. Both agree.

    THE ORDER IS THE INSTRUMENT. A shared engine is safe exactly when scanning
    leaves nothing behind that changes the next scan, and that is how such state
    would show itself: a warmed cache, a retained match or a mutated counter
    makes the backwards pass disagree with the forwards one on some document.
    Running the same order twice would hide precisely the defect being looked
    for.

    `minimum` guards the control against becoming vacuous on a module whose
    documents were renamed out of the pattern this collects.
    """
    assert len(documents) >= minimum, (
        f"only {len(documents)} documents collected; this control would be "
        f"checking almost nothing. Either the module's fixtures are not "
        f"upper-case module constants, or it should not be using this control.")

    def sweep(names):
        return {name: {f["id"] for f in engine.scan(documents[name], channel).findings}
                for name in names}

    forwards = sweep(sorted(documents))
    backwards = sweep(sorted(documents, reverse=True))
    differing = sorted(n for n in documents if forwards[n] != backwards[n])
    assert not differing, (
        f"one engine gave different findings on the second pass for "
        f"{differing}. Scanning is leaving state behind, so these tests may not "
        f"share an engine. Move the module back to the function-scoped `engine` "
        f"fixture and say why in the same commit.")
