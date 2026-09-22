#!/bin/zsh
# P4 DOES THE REFUSAL NAME ITSELF. Round 1 pinned a real defect: a poisoned
# EXPECT: tools/list was refused with rule_ids [] and inspected_utf8_bytes 0,
# EXPECT: while the same poison in tools/call named its rules. This round the
# EXPECT: defect is FIXED, so the pin is inverted and this probe is the proof.
# EXPECT: Drives the REAL binary over a pty. Exit non-zero if the envelope for
# EXPECT: a refused listing carries an empty rule_ids. No counts stated here --
# EXPECT: read the ids it prints and judge whether they are the DECIDING rules
# EXPECT: rather than a union accumulated across pages.
D=$(cd $(dirname $0)/.. && pwd)
# THE EXIT STATUS IS PYTEST'S, NEVER THE PAGER'S. This piped pytest into
# `tail` and returned TAIL's status, so a failing run exited 0 and the probe
# reported a pass it had not seen. Reviewer found it; it is the same trap that
# cost two measurements elsewhere on the same day. Output goes to a file, the
# status is captured from pytest itself, and the tail is only for reading.
out="$D/logs/p4.out"
mkdir -p "$D/logs"
cd "$D/head" || exit 2
PYTHONPATH="$D/head" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 python3 -m pytest \
  tests/proxy/test_poisoned_listing_end_to_end.py -q \
  -k "names_the_rule or stopped_on_the_wire" > "$out" 2>&1
rc=$?
tail -15 "$out"
echo "P4 pytest exit=$rc"
exit $rc
