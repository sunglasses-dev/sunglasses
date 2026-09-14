# The nightly gauntlet report

What our own adversarial harness proves each night, including where it proves
nothing. Built against ASTRA's design verdict of 2026-09-14 (E1 to E10). This is
the implementation of the amended design; it is **not published** and publication
is not authorised by the design GO.

## The rule that decides everything

No number on the page is typed by a human. Every figure renders from a committed
artifact this code wrote, and carries `data-bound` naming the field it came from.
A hand typed number is how `/about` told visitors 924 for months when the answer
was 962, and how the demo said 1,540 while it served 1,437.

The corollary matters more: **when the artifact is missing, stale or refused, the
page says so instead of rendering the last good numbers.** A dashboard that
quietly shows yesterday's green is worse than no dashboard, because from outside
it is indistinguishable from a system that ran and passed.

## The pieces

| file | what it is |
|---|---|
| `schema.py` | the closed vocabularies. States and reason codes, so nothing is overloaded onto `null`, `false` or `0` |
| `capability_map.json` | the reviewed classification of what needs the real route. Human authored inventory with citations; **currently unreviewed** |
| `classify.py` | buckets every remaining capability across every blocked variant, before any aggregate exists |
| `produce.py` | the supervisor. Measures, and emits a schema valid terminal report even when it refuses |
| `validate.py` | reads the artifact as a hostile reader would and recomputes every total from the manifests beneath it |
| `render.py` | static HTML from a validated artifact, and a refusal to build one from an invalid artifact |
| `publish.py` | selects the latest attempt, never the latest success, and refuses a stale overwrite |
| `guard_sweep.py` | mutates every guard and reports which ones no control catches |

## Running it

    python3 produce.py          # writes ../boundary/evidence/nightly.json, exit 3 on refusal
    python3 -m pytest tests -q  # the acceptance controls
    python3 guard_sweep.py      # exit 0 only when every guard is covered

## What it says today, and why that is the point

It **refuses**. Exit 3. Six operations have no reviewed capability
classification, so the ceiling renders `not computed` with those six named,
rather than a number. The FIT and method accounting panels render `unavailable`,
because neither has an examiner authored record that declares its own scope.

Two traps found while binding those panels, both of which would have published a
true number under a false label:

- the delivered mutation plan holds **73** entries over 7 requirements, which is
  not the 119 mutation examination manifest
- the delivered ledger record counts **34** charges for a single run, which is
  not the 36 of the cumulative authorised scope

Either one, rendered under the other's label, would have been a lie with a
citation attached.

## Three things learned building it, all recorded because they were nearly missed

**A blocked variant is full of operations we drive fine.** The first classifier
treated every step as a remaining need, so `send_file` appeared on a list of open
route questions. A need is what this adapter *cannot* do today.

**A guard that only fires on a perfect score is not a guard.** The mutation
completeness check fired only when rejected equalled total, so 119 of 122 with
three errored mutants passed silently. The arithmetic was fine; the run was not.

**The first guard sweep reported 42 of 44 guards untested, and was itself the
defect.** The mutation was a literal replace that missed every call written
across two lines, so the stimulus never applied and the suite stayed green for
the most boring possible reason. A green mutation row is a harness defect until
the stimulus is proven, exactly like a red one. The sweep now aborts if a
substitution does not change the file.
