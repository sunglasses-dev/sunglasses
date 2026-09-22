#!/bin/zsh
# P2 THE FP SWEEP on api_response. Widening a channel widens exposure, so this
# ran BEFORE the siblings existed and runs again here.
# EXPECT: no counts stated. Exit code is the verdict. Read it together with p3:
# EXPECT: zero false positives on rules that match NOTHING is the same number
# EXPECT: as zero on rules that are precise, and p3 is what tells them apart.
D=$(cd $(dirname $0)/.. && pwd); PYTHONUNBUFFERED=1 python3 "$D/probes/_p2.py" "$D"
