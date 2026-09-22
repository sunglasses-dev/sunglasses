#!/bin/zsh
# P4 the mutation battery. THE REVIEWER WRITES NOTHING — every tree under
# mutants/ was built and verified on disk before the round started, each
# carrying exactly one defect. This driver only reads and executes.
# EXPECT: and no row below it means anything.
# EXPECT: this wrapper states NO counts. Round 1 found its numbers stale,
# EXPECT: they were re-derived by hand, the fixtures then moved, and round 2
# EXPECT: found them stale again. A number in a comment is a claim nobody
# EXPECT: checks. The driver prints what it DERIVED beside what it measured,
# EXPECT: and its EXIT CODE is the verdict -- 0 pass, non-zero fail.
D=$(cd $(dirname $0)/.. && pwd)
PYTHONUNBUFFERED=1 python3 "$D/probes/_p4.py" "$D"
