# Contributing to Sunglasses

Thanks for wanting to help protect AI agents. Here's how to get started.

## Quick Setup

```bash
git clone https://github.com/sunglasses-dev/sunglasses.git
cd sunglasses
pip install -e ".[dev]"
pytest
```

## Ways to Contribute

### Add a Detection Pattern (Easiest)
1. Look at `attack-db/attacks/` for the JSON pattern format and `sunglasses/patterns.py` for the runtime patterns
2. Add your pattern with: regex, category, severity, description
3. Add a test case in `tests/`
4. Run `pytest` — all tests must pass
5. Submit a PR

### Add Language Support
We detect prompt injection in 23 languages. If you speak a language natively, you can add patterns that catch real-world injection attempts in that language.

### Report False Positives
If Sunglasses flags something that isn't an attack, open an issue with the text that triggered it. False positives hurt trust — we fix them fast.

### Improve Documentation
README improvements, examples, tutorials — all welcome.

## The fixture rule

**Every pattern PR needs two fixtures: one the pattern must fire on, and one it
must not.**

A pattern that only proves it fires has not been shown to discriminate. `.*`
catches every attack in the corpus and every line of your users' clean code with
it — and false positives are how a security tool gets uninstalled. The benign
control is what turns "this matched" into "this matched *the right thing*".

```python
# tests/test_my_pattern.py
from sunglasses.engine import SunglassesEngine


def test_pattern_fires_on_the_attack():
    result = SunglassesEngine().scan("<the attack string>")
    assert result.decision == "block"
    assert any(f["id"] == "GLS-XXX-001" for f in result.findings)


def test_pattern_stays_quiet_on_benign_content():
    # Realistic content from the same domain — documentation, a code comment,
    # a support email. Not "hello world": prove it against something that
    # plausibly *could* have tripped it.
    result = SunglassesEngine().scan("<ordinary content that looks similar>")
    assert not any(f["id"] == "GLS-XXX-001" for f in result.findings)
```

### A worked example

[PR #31](https://github.com/sunglasses-dev/sunglasses/pull/31) by
[@Lucas-FManager](https://github.com/Lucas-FManager) added Vietnamese prompt
injection and credential exfiltration patterns — a native speaker contributing
coverage nobody on the team could have written. It is the right shape for a
pattern contribution: real attack strings, both the `attack-db/` JSON and the
runtime patterns updated together, and tests asserting each new ID fires and is
present in the catalog (`tests/test_vietnamese_multilingual_patterns.py`).

What that PR predates is the second half. Landing the same contribution today,
we would also ask for a benign Vietnamese control — ordinary Vietnamese text
that must *not* fire — so the pattern is shown to discriminate rather than just
to match. That is the rule this section adds, not a criticism of the PR.

## Other rules
- Keep it simple — one pattern per PR is fine
- Be specific in PR descriptions — what does this catch?
- Pattern IDs follow `GLS-<PREFIX>-<NNN>` and must not collide with an existing ID
- Don't hand-edit published claims (README stats, version, CHANGELOG) — those are
  generated from the truth layer and a manual edit gets overwritten

## Found a bypass?

That is the most useful thing you can bring us, and reporting one is a
contribution, not an attack on the project.

- **Affects a real system, or is a working exploit** → report it privately via
  [SECURITY.md](SECURITY.md). We credit you in the release notes.
- **Otherwise** → open a *Bypass or false positive* issue with the exact input,
  the exact command, and the exit code you expected versus the one you got.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Reports go
to contact@sunglasses.dev.

## Questions?
Open an issue or reach out at contact@sunglasses.dev
