# AGENTS.md — working in this repo as an AI agent

For coding agents (Claude Code, Codex, Cursor, Aider, or a human who wants the
short version). Everything here is checkable against the repo; if a line stops
being true, fix the line.

## What this project is, in one paragraph

Sunglasses inspects content *before* an AI agent acts on it, and reports what it
found **and what it could not read**. The whole value is that second half. A tool
that says "clean" about a file it never opened is worse than no tool, because
someone will trust it. Every change you make here is judged against that.

## Run the tests

```bash
python3 -m pytest -q          # from the repo root, with NO path argument
```

`pytest.ini` pins `testpaths` on purpose. On 2026-08-28 two honest reviewers
measured 780 and 778 passing on the *same commit*, because two root-level tests
only collect when pytest runs from root scope. **Passing an explicit path
re-creates that ambiguity** — a bare run from the root is the only measurement
anyone should quote.

It still reproduces. Try it:

```
$ python3 -m pytest -q --collect-only         # 1397 tests collected
$ python3 -m pytest -q --collect-only tests   # 1395 tests collected
```

Two tests, same commit, different answer — decided entirely by an argument you
did or did not type.

## What CI actually runs

`.github/workflows/pattern-integrity.yml`, on **six** Python versions —
3.9, 3.10, 3.11, 3.12, 3.13, 3.14 — all **fully blocking**, none informational.

It installs real native decoders (`tesseract-ocr`, `libzbar0`, `ffmpeg`) and
pins Pillow (12.3.0; 3.9 necessarily takes 11.3.0). That is not incidental: a
missing decoder turns a real finding into silence, so a green run without them
proves nothing about media scanning. If you touch image, QR, PDF or audio paths,
assume the decoder version matters until you have shown it does not.

## The truth layer — do not hand-edit published numbers

`stats/current.json` is the single source for every published figure: pattern
count, category count, keyword count, language count, version. README stats,
site JSON-LD and package metadata are generated from it.

- **Never** hand-edit a number in `README.md`, the CHANGELOG, or the version
  string to make something look consistent. It will be overwritten, and in the
  meantime you have published a claim with no generator behind it.
- `stats/verified-sources.yml` holds every URL we cite, with the date it was last
  fetched and confirmed 200. **Never guess a URL from memory** — if the one you
  need is not there, fetch it yourself and add it with today's date.

## The fixture rule

**Every pattern change needs two fixtures: one it must fire on, and one it must
not.** See [CONTRIBUTING.md](CONTRIBUTING.md) for the worked example.

A pattern with only a positive test has not been shown to discriminate — `.*`
passes that bar. The benign control is the whole test. Keep `attack-db/`,
`sunglasses/data/attacks/` and `sunglasses/patterns.py` in sync; a pattern in one
and not the others is a half-landed change.

## The exit-code contract

`0` clean · `1` threat found · `2` usage or operational error · `3` incomplete
inspection. Precedence is `1 > 3 > 2 > 0`.

`0` and `3` must never collapse into each other. "I read it and found nothing"
and "I could not open it, so I saw nothing" are different facts, and a CI job
consuming our exit status is entitled to tell them apart. If you are changing
anything that returns a status, prove all four paths still return what they say.

## Things that look helpful and are not

- **Widening a regex to make a test pass.** A pattern broad enough to catch every
  attack in the corpus catches your users' clean code too, and false positives
  are how a security tool gets uninstalled.
- **Silencing an "incomplete" report** because it is noisy. That report is the
  product.
- **Adding a badge, metric, or claim you have not verified.** If you cannot point
  at the command that produced a number, do not publish the number.
- **`git push` to `main`.** Branch and open a PR, always.

## What to do when you are unsure

Say so in the PR, in the section the template gives you for exactly this. A
disclosed limitation costs nothing. A quiet one gets found by whoever was
depending on it.

## Security

Found a bypass? That is a contribution, and it is the most useful thing you can
bring us. If it affects a real system or is a working exploit, report it
privately — see [SECURITY.md](SECURITY.md) — rather than in a public issue or PR.
