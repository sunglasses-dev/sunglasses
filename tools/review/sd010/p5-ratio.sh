#!/bin/zsh
# P5 the cost gate, with the number shown. A RATIO, never seconds: the engine is
# built WITHOUT the rule and WITH it in the same process, over the same shapes.
# The shapes and the gate value are imported from the test module, so what is
# printed here cannot drift from what CI enforces.
# EXPECT: this wrapper states NO counts. Round 1 found its numbers stale,
# EXPECT: they were re-derived by hand, the fixtures then moved, and round 2
# EXPECT: found them stale again. A number in a comment is a claim nobody
# EXPECT: checks. The driver prints what it DERIVED beside what it measured,
# EXPECT: and its EXIT CODE is the verdict -- 0 pass, non-zero fail.
D=$(cd $(dirname $0)/.. && pwd)
PYTHONUNBUFFERED=1 python3 "$D/probes/_p5.py" "$D"
