# tool-metadata `-API` sibling review harness

The probes that graded the fourteen `-API` siblings, living beside the rules
they grade instead of only in a tmp package. Rebuild a package with
`git archive`, drop these in as `probes/`, and run them by path.

| probe | asks |
|---|---|
| p1 | is each sibling's record its parent's, field for field |
| p2 | does the api_response corpus stay clean |
| p3 | do they actually DETECT — the question a dead generation passes |
| p4 | does a refused listing NAME the rule that refused it (real binary, pty) |

## Read p2 and p3 together or they lie to you

A generation once produced fourteen siblings that loaded, carried the right
ids, raised the pattern count by exactly 14 and matched NOTHING, because each
regex was emitted as `r` plus its `repr`. **The false-positive sweep over that
dead set came back a clean zero** — true, and worthless: a rule that matches
nothing has no false positives either. Only p3 caught it.

## What round 1 found in these probes, and what changed

The reviewer graded the HARNESS as well as the rules, and was right three times.

- **p1 compared `regex` and `keywords` only.** Any other behaviour-carrying
  field could differ between a sibling and its parent and p1 still called the
  predicates identical. It now compares EVERY key minus a declared allowlist
  (`id`, `channel`, `name`), and a key set that differs at all is its own
  failure. Measured on a tree with one sibling's `severity` flipped: the old
  probe exits 0 SPINE CLEAN, this one exits 1 and names the rule and the field.
  Widening it immediately surfaced a fourth intentional difference — every
  sibling is `<parent name> (api_response)` — so rather than skip `name`, the
  probe ASSERTS that convention and catches a sibling renamed into something an
  operator would read as a different rule.
- **p3 let an unbuildable stimulus leave through the pass door.** A sibling
  whose trigger could not be generated was counted, printed, and then ignored
  by an exit that keyed on `silent` alone. "We could not test it" now exits 3
  as UNMEASURED, because the whole reason p3 exists is that untested and tested
  once looked the same here.
- **p4 returned the PAGER's exit status.** It piped pytest into `tail`, so a
  failing run exited 0 and the probe reported a pass it never saw. Output goes
  to a file, the status is captured from pytest, and the tail is only for
  reading.

**And one the reviewer did not raise: an empty subject is not a clean one.** If
the sibling selection matches nothing — a renamed family, a filter that names
the branch it was written on — every count is 0 and the probe exits CLEAN
having measured no rule at all. p1 and p3 now refuse to run on an empty set.
