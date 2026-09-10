<!--
Thanks for contributing. Delete any section that does not apply — a short, honest
PR beats a long one with boxes ticked for things nobody ran.
-->

## What this changes

<!-- One or two sentences. What does this catch, fix, or clarify? -->

## Why

<!-- What went wrong without it, or what was inaccurate. Link an issue if there is one. -->

## If this adds or changes a detection pattern

Every pattern needs **both** halves. One without the other is not a pattern, it is a guess:

- [ ] **Positive fixture** — a sample the pattern must fire on, in `tests/`
- [ ] **Benign control** — realistic content that must **not** fire, in `tests/`
- [ ] Pattern ID follows `GLS-<PREFIX>-<NNN>` and does not collide with an existing one
- [ ] `pytest` passes locally

Why the control matters: a pattern that only proves it fires has not been shown
to discriminate. A regex broad enough to catch everything catches everyone's
clean code too, and false positives are how a security tool gets uninstalled.

## Checks

- [ ] `pytest` passes
- [ ] I did not change published claims (README stats, version, CHANGELOG) unless
      that is the point of this PR — those are generated from the truth layer

## Anything a reviewer should know

<!--
Limits, guesses, a case you could not test, a number you took from somewhere else.
Say it here rather than letting the reviewer find it. This is not held against a PR.
-->

---

**Found a bypass?** Please do not attach a working exploit to a public PR —
report it privately via [SECURITY.md](../SECURITY.md) and we will credit you in
the release notes.
