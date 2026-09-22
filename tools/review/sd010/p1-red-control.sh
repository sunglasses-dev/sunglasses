#!/bin/zsh
# P1 RED CONTROL. The gap must reproduce on BASE before anything HEAD says means
# anything. Prints counts and verdicts only -- never a fixture body.
# EXPECT: this wrapper states NO counts. Round 1 found its numbers stale,
# EXPECT: they were re-derived by hand, the fixtures then moved, and round 2
# EXPECT: found them stale again. A number in a comment is a claim nobody
# EXPECT: checks. The driver prints what it DERIVED beside what it measured,
# EXPECT: and its EXIT CODE is the verdict -- 0 pass, non-zero fail.
D=$(cd $(dirname $0)/.. && pwd)
PYTHONUNBUFFERED=1 python3 "$D/probes/_p1.py" "$D"
